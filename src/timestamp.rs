use std::{convert::TryInto, time::SystemTime};

use crate::transport::Clock;

/// Milliseconds since the Unix epoch, on `clock`.
pub(crate) fn epoch_millis(clock: &dyn Clock) -> u64 {
    clock
        .now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("the clock reads after the Unix epoch")
        .as_millis()
        .try_into()
        .expect("millis overflow")
}
