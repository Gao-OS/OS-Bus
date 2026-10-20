#define _GNU_SOURCE
#include <signal.h>
#include <string.h>
#include <unistd.h>

/* Deliberately malformed bridge replacement, built only in the private app. */
int main(int argc, char **argv) {
    if (argc != 2) return 99;
    const char *name = argv[1];
    unsigned char record[17] = {'G', 'H', 'B', 1, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 42};
    size_t length = 16;
    int result = 0;
    if (!strcmp(name, "org.fixture.Missing")) length = 0;
    if (!strcmp(name, "org.fixture.Truncated")) length = 8;
    if (!strcmp(name, "org.fixture.Extra")) length = 17;
    if (!strcmp(name, "org.fixture.Reserved")) record[7] = 1;
    if (!strcmp(name, "org.fixture.Version")) record[3] = 2;
    if (!strcmp(name, "org.fixture.Stage")) record[5] = 9;
    if (!strcmp(name, "org.fixture.UnknownKind")) record[4] = 6;
    if (!strcmp(name, "org.fixture.ExitRange")) { record[10] = 1; record[11] = 0; }
    if (!strcmp(name, "org.fixture.SignalRange")) { record[4] = 4; record[11] = 65; }
    if (!strcmp(name, "org.fixture.ZeroErrno")) { record[4] = 2; record[5] = 9; }
    if (!strcmp(name, "org.fixture.NotStarted")) { record[4] = 1; record[5] = 7; record[11] = 11; }
    if (!strcmp(name, "org.fixture.ExecFailed")) { record[4] = 2; record[5] = 9; record[11] = 2; }
    if (!strcmp(name, "org.fixture.ObservationFailed")) { record[4] = 5; record[5] = 10; record[11] = 10; }
    if (!strcmp(name, "org.fixture.Abnormal")) result = 1;
    if (!strcmp(name, "org.fixture.Fragmented")) {
        for (size_t i = 0; i < length; i++) {
            char acknowledgement;
            if (write(1, record + i, 1) != 1 || read(0, &acknowledgement, 1) != 1) return 98;
        }
    } else if (write(1, record, length) != (ssize_t)length) return 97;
    if (!strcmp(name, "org.fixture.Signal")) raise(SIGKILL);
    return result;
}
