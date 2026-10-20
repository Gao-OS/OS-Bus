#define _GNU_SOURCE
#include <gio/gio.h>
#include <gio/gunixfdlist.h>
#include <glib-unix.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <unistd.h>

extern char **environ;
static GMainLoop *loop;
static const char *interface = "org.foundation.Activation";
static const char *path = "/org/foundation/Activation";
static const char xml[] = "<node><interface name='org.foundation.Activation'>"
  "<method name='Echo'><arg type='s' direction='in'/><arg type='s' direction='out'/></method>"
  "<method name='ReadAndReturnFD'><arg type='h' direction='in'/><arg type='h' direction='out'/><arg type='s' direction='out'/></method>"
  "<method name='Quit'/></interface></node>";

static void quote(FILE *f, const char *s) {
    fputc('"', f);
    for (const unsigned char *p=(const unsigned char *)s; *p; p++) {
        if (*p=='"' || *p=='\\') { fputc('\\',f); fputc(*p,f); }
        else if (*p<32) fprintf(f,"\\u%04x",*p);
        else fputc(*p,f);
    }
    fputc('"',f);
}

/* libc-only main-entry witness after ELF loading, before explicit GLib/bus APIs. */
static void witness(const char *mode) {
    uid_t ru,eu,su; gid_t rg,eg,sg,groups[64];
    if (getresuid(&ru,&eu,&su) || getresgid(&rg,&eg,&sg)) exit(90);
    int count=getgroups(64,groups); if (count<0) exit(91);
    char stat[4096]; FILE *proc=fopen("/proc/self/stat","r");
    if (!proc || !fgets(stat,sizeof(stat),proc)) exit(92);
    fclose(proc);
    struct { int fd; char target[4096]; } rows[256]; int n=0;
    DIR *dir=opendir("/proc/self/fd"); if (!dir) exit(93);
    struct dirent *entry;
    while ((entry=readdir(dir))) {
        char *end; long fd=strtol(entry->d_name,&end,10);
        if (*end || fd<0 || fd==dirfd(dir)) continue;
        if (n==256) exit(94);
        char link[64]; snprintf(link,sizeof(link),"/proc/self/fd/%ld",fd);
        ssize_t size=readlink(link,rows[n].target,sizeof(rows[n].target)-1);
        if (size<0) exit(95);
        rows[n].target[size]=0; rows[n++].fd=(int)fd;
    }
    closedir(dir);
    char file[256]; snprintf(file,sizeof(file),"/run/osbus-p10/witness/%s.json",mode);
    int fd=open(file,O_CREAT|O_EXCL|O_WRONLY|O_NOFOLLOW|O_CLOEXEC,0600); if (fd<0) exit(96);
    FILE *f=fdopen(fd,"w"); if (!f) exit(97);
    fprintf(f,"{\"pid\":%ld,\"uids\":[%u,%u,%u],\"gids\":[%u,%u,%u],\"groups\":[",(long)getpid(),ru,eu,su,rg,eg,sg);
    for (int i=0;i<count;i++) fprintf(f,"%s%u",i?",":"",groups[i]);
    fputs("],\"stat\":",f); quote(f,stat); fputs(",\"environment\":[",f);
    for (int i=0;environ[i];i++) {
        if (i>=64 || strlen(environ[i])>4096) exit(98);
        if (i) fputc(',',f);
        quote(f,environ[i]);
    }
    fputs("],\"fds\":[",f); int emitted=0;
    for (int fdnum=0;fdnum<1024;fdnum++) for (int i=0;i<n;i++) if (rows[i].fd==fdnum) {
        if (emitted++) fputc(',',f);
        fprintf(f,"{\"fd\":%d,\"target\":",fdnum); quote(f,rows[i].target); fputc('}',f);
    }
    /* FDs beyond the loop's output bound are still represented and rejected. */
    for (int i=0;i<n;i++) if (rows[i].fd>=1024) {
        if (emitted++) fputc(',',f);
        fprintf(f,"{\"fd\":%d,\"target\":",rows[i].fd); quote(f,rows[i].target); fputc('}',f);
    }
    fputs("]}\n",f); if (fclose(f)) exit(99);
}

static void method(GDBusConnection *connection, const gchar *sender, const gchar *object,
                   const gchar *iface, const gchar *member, GVariant *params,
                   GDBusMethodInvocation *call, gpointer data) {
    (void)connection;(void)sender;(void)object;(void)iface;(void)data;
    if (!strcmp(member,"Echo")) { const char *text; g_variant_get(params,"(&s)",&text); g_dbus_method_invocation_return_value(call,g_variant_new("(s)",text)); }
    else if (!strcmp(member,"Quit")) { g_dbus_method_invocation_return_value(call,NULL); g_main_loop_quit(loop); }
    else if (!strcmp(member,"ReadAndReturnFD")) {
        gint32 index; g_variant_get(params,"(h)",&index); GError *error=NULL;
        GUnixFDList *in=g_dbus_message_get_unix_fd_list(g_dbus_method_invocation_get_message(call));
        int fd=in?g_unix_fd_list_get(in,index,&error):-1; char text[128]; ssize_t n=fd<0?-1:pread(fd,text,sizeof(text)-1,0);
        if (n<0) { g_clear_error(&error); g_dbus_method_invocation_return_dbus_error(call,"org.freedesktop.DBus.Error.InvalidArgs","invalid fixture descriptor"); }
        else { text[n]=0; GUnixFDList *out=g_unix_fd_list_new(); int id=g_unix_fd_list_append(out,fd,&error);
            if (id<0) g_dbus_method_invocation_return_gerror(call,error);
            else g_dbus_method_invocation_return_value_with_unix_fd_list(call,g_variant_new("(hs)",id,text),out);
            g_clear_error(&error);g_object_unref(out); }
        if (fd>=0) close(fd);
    }
}
static const GDBusInterfaceVTable vtable={.method_call=method};
static gboolean stop(gpointer data) { (void)data;g_main_loop_quit(loop);return G_SOURCE_REMOVE; }
static GDBusConnection *bus(void) {
    GError *error=NULL;GDBusConnection *c=g_bus_get_sync(G_BUS_TYPE_SYSTEM,NULL,&error);
    if (!c) { fprintf(stderr,"bus: %s\n",error->message);exit(20); } return c;
}
static GVariant *call(GDBusConnection *c,const char *name,const char *iface,const char *member,GVariant *params,GError **error) {
    return g_dbus_connection_call_sync(c,name,!strcmp(iface,"org.freedesktop.DBus")?"/org/freedesktop/DBus":path,iface,member,params,NULL,G_DBUS_CALL_FLAGS_NO_AUTO_START,3000,NULL,error);
}
static int client(int argc,char **argv) {
    if (argc<4) return 21;
    GDBusConnection *c=bus();GError *error=NULL;GVariant *reply=NULL;
    if (!strcmp(argv[2],"owner")) {
        reply=call(c,"org.freedesktop.DBus","org.freedesktop.DBus","GetNameOwner",g_variant_new("(s)",argv[3]),&error);
        if (reply) { const char *owner;g_variant_get(reply,"(&s)",&owner);char *copy=g_strdup(owner);
            GVariant *u=call(c,"org.freedesktop.DBus","org.freedesktop.DBus","GetConnectionUnixUser",g_variant_new("(s)",copy),&error);
            GVariant *p=call(c,"org.freedesktop.DBus","org.freedesktop.DBus","GetConnectionUnixProcessID",g_variant_new("(s)",copy),&error);
            if (!u || !p) return 22;
            guint32 uid,pid;g_variant_get(u,"(u)",&uid);g_variant_get(p,"(u)",&pid);
            printf("{\"owner\":\"%s\",\"uid\":%u,\"pid\":%u}\n",copy,uid,pid);
            g_free(copy);g_variant_unref(u);g_variant_unref(p); }
    } else if (!strcmp(argv[2],"fd")) {
        int fd=memfd_create("p10-readback",MFD_CLOEXEC);const char text[]="installed-helper-FD";
        if (fd<0 || write(fd,text,sizeof(text)-1)!=(ssize_t)sizeof(text)-1) return 23;
        GUnixFDList *in=g_unix_fd_list_new();int index=g_unix_fd_list_append(in,fd,&error);GUnixFDList *out=NULL;
        reply=g_dbus_connection_call_with_unix_fd_list_sync(c,argv[3],path,interface,"ReadAndReturnFD",g_variant_new("(h)",index),NULL,G_DBUS_CALL_FLAGS_NO_AUTO_START,3000,in,&out,NULL,&error);
        close(fd);g_object_unref(in);
        if (reply) { gint32 received;const char *value;g_variant_get(reply,"(h&s)",&received,&value);int copy=g_unix_fd_list_get(out,received,&error);
            char readback[128];ssize_t n=copy<0?-1:pread(copy,readback,sizeof(readback)-1,0);
            if (n!=(ssize_t)sizeof(text)-1 || memcmp(readback,text,n) || strcmp(value,text) || g_unix_fd_list_get_length(out)!=1) return 24;
            printf("{\"fd_readback\":true,\"fds\":1,\"contents\":\"%s\"}\n",value);close(copy);g_object_unref(out); }
    } else { const char *member=!strcmp(argv[2],"quit")?"Quit":"Echo";
        reply=call(c,argv[3],interface,member,!strcmp(member,"Echo")?g_variant_new("(s)","installed-helper"):NULL,&error);
        if (reply) { if (!strcmp(member,"Echo")) { const char *text;g_variant_get(reply,"(&s)",&text); if (strcmp(text,"installed-helper")) return 25; }
            puts("{\"ok\":true}"); }
    }
    if (!reply) { char *remote=error?g_dbus_error_get_remote_error(error):NULL;
        printf("{\"error\":\"%s\"}\n",remote?remote:"local-failure");g_free(remote);g_clear_error(&error);g_object_unref(c);return 1; }
    g_variant_unref(reply);g_object_unref(c);return 0;
}
static int guest_marker(void) {
    const char expected[]="isolated-vm\n"; char bytes[sizeof(expected)];
    FILE *file=fopen("/etc/osbus-p10-guest","rb"); if (!file) return 0;
    size_t size=fread(bytes,1,sizeof(bytes),file); int failed=ferror(file);
    if (fclose(file)) return 0;
    return !failed && size==sizeof(expected)-1 && !memcmp(bytes,expected,size);
}
int main(int argc,char **argv) {
    if (!guest_marker()) return 89;
    if (argc>1 && !strcmp(argv[1],"client")) return client(argc,argv);
    if (argc!=2 || (strcmp(argv[1],"Echo") && strcmp(argv[1],"Flood") && strcmp(argv[1],"Exit0") && strcmp(argv[1],"Live"))) return 2;
    witness(argv[1]);
    if (!strcmp(argv[1],"Exit0")) return 0;
    loop=g_main_loop_new(NULL,FALSE);g_unix_signal_add(SIGTERM,stop,NULL);
    if (!strcmp(argv[1],"Live")) {
        int ready=open("/run/osbus-p10/witness/Live.ready",O_CREAT|O_EXCL|O_WRONLY|O_NOFOLLOW|O_CLOEXEC,0600);
        if (ready<0 || dprintf(ready,"%ld\n",(long)getpid())<0 || close(ready)) return 7;
        g_main_loop_run(loop);g_main_loop_unref(loop);return 0;
    }
    if (!strcmp(argv[1],"Flood")) { char bytes[4096];memset(bytes,'x',sizeof(bytes));for(int i=0;i<8192;i++) if(write(1,bytes,sizeof(bytes))<0 || write(2,bytes,sizeof(bytes))<0)return 3; }
    GDBusConnection *c=bus();GError *error=NULL;GDBusNodeInfo *node=g_dbus_node_info_new_for_xml(xml,&error);
    if(!node || !g_dbus_connection_register_object(c,path,node->interfaces[0],&vtable,NULL,NULL,&error)) return 4;
    char name[128];snprintf(name,sizeof(name),"org.foundation.Activation.%s",argv[1]);
    GVariant *reply=call(c,"org.freedesktop.DBus","org.freedesktop.DBus","RequestName",g_variant_new("(su)",name,4),&error);
    if(!reply)return 5;
    guint32 status;g_variant_get(reply,"(u)",&status);if(status!=1)return 6;g_variant_unref(reply);
    g_main_loop_run(loop);g_dbus_connection_flush_sync(c,NULL,NULL);g_dbus_node_info_unref(node);g_object_unref(c);g_main_loop_unref(loop);return 0;
}
