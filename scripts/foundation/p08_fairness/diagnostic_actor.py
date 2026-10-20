"""Original frozen Worker plus observed-only drain command; never infers admissions."""
import select

from actor import Worker, main

original_command = Worker.command


def command(worker, request):
    if request['op'] == 'diagnostic_observed':
        # Controller first barriers Router/Peer and observes egress zero. Every
        # successful Unix write is already readable; consume remaining kernel data.
        while select.select([worker.client.sock], [], [], 0)[0]:
            worker.ingest()
        assert len(worker.calls) == request['calls'], ('diagnostic held calls', len(worker.calls))
        return {'delivered': list(worker.messages.values()), 'calls': list(worker.calls.values()),
                'complete_delivery_proof': 'NOT_MEASURED'}
    return original_command(worker, request)


Worker.command = command

if __name__ == '__main__':
    main()
