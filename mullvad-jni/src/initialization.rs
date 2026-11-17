//! Keep occupied-context recovery ordered before replacement initialization.

pub(crate) fn prepare<T>(
    stored: &mut Option<T>,
    retryable: impl FnOnce(&T) -> bool,
    retry: impl FnOnce(&mut T) -> Result<(), String>,
) -> Result<(), String> {
    let Some(context) = stored.as_mut() else {
        return Ok(());
    };
    if !retryable(context) {
        return Err("Mullvad daemon still owns its runtime or pending cleanup".into());
    }
    retry(context)?;
    // A failed retry returns above with the same owner still stored. Only a
    // positively completed cleanup releases its runtime and service references.
    stored.take();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    struct Context {
        running: bool,
        task_failed: bool,
        failure: Option<u32>,
        attempts: usize,
        fail: bool,
        dropped: Arc<AtomicUsize>,
    }
    impl Drop for Context {
        fn drop(&mut self) {
            self.dropped.fetch_add(1, Ordering::SeqCst);
        }
    }
    fn initialize(stored: &mut Option<Context>) -> Result<(), String> {
        prepare(
            stored,
            |c| !c.running && !c.task_failed && c.failure.is_some(),
            |c| {
                c.attempts += 1;
                let exact = c.failure.take().unwrap();
                if c.fail {
                    c.failure = Some(exact);
                    Err("retained release failure".into())
                } else {
                    Ok(())
                }
            },
        )
    }

    #[test]
    fn initialization_retries_only_retained_shutdown_and_never_discards_failed_ownership() {
        let dropped = Arc::new(AtomicUsize::new(0));
        let mut empty: Option<Context> = None;
        prepare(
            &mut empty,
            |_| panic!("empty predicate"),
            |_| panic!("empty retry"),
        )
        .unwrap();
        for (running, task_failed, failure) in [
            (true, false, None),
            (true, false, Some(7)),
            (false, true, None),
            (false, false, None),
        ] {
            let mut stored = Some(Context {
                running,
                task_failed,
                failure,
                attempts: 0,
                fail: false,
                dropped: dropped.clone(),
            });
            assert!(initialize(&mut stored).is_err());
            assert_eq!(stored.as_ref().unwrap().attempts, 0);
            assert_eq!(stored.as_ref().unwrap().failure, failure);
        }
        assert_eq!(dropped.load(Ordering::SeqCst), 4);
        let mut stored = Some(Context {
            running: false,
            task_failed: false,
            failure: Some(41),
            attempts: 0,
            fail: true,
            dropped: dropped.clone(),
        });
        assert_eq!(
            initialize(&mut stored),
            Err("retained release failure".into())
        );
        assert_eq!(stored.as_ref().unwrap().failure, Some(41));
        assert_eq!(stored.as_ref().unwrap().attempts, 1);
        assert_eq!(dropped.load(Ordering::SeqCst), 4);
        stored.as_mut().unwrap().fail = false;
        initialize(&mut stored).unwrap();
        assert!(stored.is_none());
        assert_eq!(dropped.load(Ordering::SeqCst), 5);
    }
}
