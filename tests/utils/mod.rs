use std::time::Duration;
use std::sync::mpsc;
use std::sync::mpsc::{TrySendError, RecvTimeoutError};

#[derive(Clone, Debug)]
pub enum TestKind {
    /// Test will pass if a success has been notified in the test duration
    ExpectSuccess,
    /// Test will pass if no failure has been notified in the test duration
    ExpectNoFailure,
}

#[derive(Clone, Debug)] // mpsc channels are clone-able to be shared between threads
pub struct StatusNotifier {
    kind: TestKind,
    tx: mpsc::SyncSender<()>,
}

impl StatusNotifier {
    pub fn notify_success(&self) {
        match self.kind {
            TestKind::ExpectSuccess => {
                match self.tx.try_send(()) {
                    Ok(()) => (),
                    Err(TrySendError::Full(_)) => (), // this means we've sent a success signal already, we don't care
                    Err(TrySendError::Disconnected(_)) => (), // Receiver disconnected when the test was still running. That's usually expected, since the callback can outlive the function that started the trace
                }
            },
            _ => (),
        }
    }

    pub fn notify_failure(&self) {
        match self.kind {
            TestKind::ExpectNoFailure => {
                match self.tx.try_send(()) {
                    Ok(()) => (),
                    Err(TrySendError::Full(_)) => (), // this means we've sent a failure signal already, we don't care
                    Err(TrySendError::Disconnected(_)) => (), // Receiver disconnected when the test was still running. That's usually expected, since the callback can outlive the function that started the trace
                }
            },
            _ => (),
        }
    }
}

#[derive(Debug)]
pub struct Status {
    notifier: StatusNotifier,
    rx: mpsc::Receiver<()>,
}

impl Status {
    pub fn new(kind: TestKind) -> Self {
        let (tx, rx) = mpsc::sync_channel(1);
        Self { notifier: StatusNotifier{kind, tx}, rx }
    }

    pub fn notifier(&self) -> StatusNotifier {
        self.notifier.clone()
    }

    pub fn assert_passed(&self) {
        let timeout = Duration::from_secs(10);

        match self.notifier.kind {
            TestKind::ExpectSuccess => {
                match self.rx.recv_timeout(timeout) {
                    Ok(()) => {
                        return;
                    },
                    Err(RecvTimeoutError::Timeout) => {
                        panic!("Test did not pass within the allowed timeout");
                    },
                    _ => panic!("Should not happen, the sending end has not hung up."),
                }
            },

            TestKind::ExpectNoFailure => {
                match self.rx.recv_timeout(timeout) {
                    Ok(()) => {
                        panic!("Test failed within the allowed timeout");
                    },
                    Err(RecvTimeoutError::Timeout) => {
                        return;
                    },
                    _ => panic!("Should not happen, the sending end has not hung up."),
                }
            }
        }
    }
}
