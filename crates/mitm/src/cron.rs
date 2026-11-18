use concord_config::mitm::LineError;
use concord_config::mitm::text::quote;
use time::{Date, Month, OffsetDateTime};

/// A 29 February schedule waits eight years across a skipped century leap year.
const SEARCH_HORIZON: i64 = 8 * 366 * 86_400;

/// The device's local time. Rust has no zone database in this workspace, so the
/// host supplies the offset in force at an instant.
pub trait LocalClock: Send + Sync {
    /// Seconds east of UTC at the Unix time `unix`.
    fn offset_at(&self, unix: i64) -> i32;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct UtcClock;

impl LocalClock for UtcClock {
    fn offset_at(&self, _unix: i64) -> i32 {
        0
    }
}

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct CronError(String);

impl From<CronError> for LineError {
    fn from(err: CronError) -> LineError {
        LineError::invalid(err.0)
    }
}

/// Five fields, or six with seconds first as Surge does. A day matching a
/// restricted day of month or weekday fires, as in Vixie cron.
#[derive(Clone, Debug)]
pub struct CronSchedule {
    second: u64,
    minute: u64,
    hour: u64,
    day: u64,
    month: u64,
    weekday: u64,
    any_day: bool,
    any_weekday: bool,
}

struct Field {
    min: u32,
    max: u32,
    names: &'static [(&'static str, u32)],
}

const MONTH_NAMES: &[(&str, u32)] = &[
    ("jan", 1),
    ("feb", 2),
    ("mar", 3),
    ("apr", 4),
    ("may", 5),
    ("jun", 6),
    ("jul", 7),
    ("aug", 8),
    ("sep", 9),
    ("oct", 10),
    ("nov", 11),
    ("dec", 12),
];

const WEEKDAY_NAMES: &[(&str, u32)] = &[
    ("sun", 0),
    ("mon", 1),
    ("tue", 2),
    ("wed", 3),
    ("thu", 4),
    ("fri", 5),
    ("sat", 6),
];

const SECONDS: Field = Field {
    min: 0,
    max: 59,
    names: &[],
};
const MINUTES: Field = Field {
    min: 0,
    max: 59,
    names: &[],
};
const HOURS: Field = Field {
    min: 0,
    max: 23,
    names: &[],
};
const DAYS: Field = Field {
    min: 1,
    max: 31,
    names: &[],
};
const MONTHS: Field = Field {
    min: 1,
    max: 12,
    names: MONTH_NAMES,
};
const WEEKDAYS: Field = Field {
    min: 0,
    max: 7,
    names: WEEKDAY_NAMES,
};

impl CronSchedule {
    pub fn parse(text: &str) -> Result<CronSchedule, CronError> {
        let mut fields: Vec<&str> = text.split_whitespace().collect();
        match fields.len() {
            5 => fields.insert(0, "0"),
            6 => {}
            count => {
                return Err(CronError(format!(
                    "cron expression {} has {count} fields, not 5 or 6",
                    quote(text)
                )));
            }
        }
        let at = |i: usize| fields.get(i).copied().unwrap_or_default();
        let (second, _) = SECONDS.parse(at(0))?;
        let (minute, _) = MINUTES.parse(at(1))?;
        let (hour, _) = HOURS.parse(at(2))?;
        let (day, any_day) = DAYS.parse(at(3))?;
        let (month, _) = MONTHS.parse(at(4))?;
        let (mut weekday, any_weekday) = WEEKDAYS.parse(at(5))?;
        if weekday & (1 << 7) != 0 {
            weekday = weekday & !(1 << 7) | 1;
        }
        Ok(CronSchedule {
            second,
            minute,
            hour,
            day,
            month,
            weekday,
            any_day,
            any_weekday,
        })
    }

    fn matches_day(&self, date: Date) -> bool {
        let day = self.day & (1 << date.day()) != 0;
        let weekday = self.weekday & (1 << date.weekday().number_days_from_sunday()) != 0;
        if self.any_day || self.any_weekday {
            day && weekday
        } else {
            day || weekday
        }
    }

    /// The first Unix second after `after` the schedule fires in local time, or
    /// `None` if none comes within eight years (February 30). A wall clock set back
    /// names an hour twice, so within a day this steps by elapsed time and fires
    /// only once the clock reads later than at `after`, as Vixie cron does.
    pub fn next(&self, after: i64, clock: &dyn LocalClock) -> Option<i64> {
        let wall = |t: i64| t + i64::from(clock.offset_at(t));
        let floor = wall(after);
        let mut t = after + 1;
        let limit = after + SEARCH_HORIZON;
        while t < limit {
            let at = OffsetDateTime::from_unix_timestamp(wall(t)).ok()?;
            let step = if self.month & (1 << u8::from(at.month())) == 0 {
                let (year, month) = match at.month() {
                    Month::December => (at.year() + 1, Month::January),
                    other => (at.year(), other.next()),
                };
                local_midnight(Date::from_calendar_date(year, month, 1).ok()?, clock)
            } else if !self.matches_day(at.date()) {
                local_midnight(at.date().next_day()?, clock)
            } else if self.hour & (1 << at.hour()) == 0 {
                t + (60 - i64::from(at.minute())) * 60 - i64::from(at.second())
            } else if self.minute & (1 << at.minute()) == 0 {
                t + 60 - i64::from(at.second())
            } else if self.second & (1 << at.second()) == 0 || wall(t) <= floor {
                t + 1
            } else {
                return Some(t);
            };
            t = step.max(t + 1);
        }
        None
    }
}

fn local_midnight(date: Date, clock: &dyn LocalClock) -> i64 {
    let wall = date.midnight().assume_utc().unix_timestamp();
    let guess = wall - i64::from(clock.offset_at(wall));
    wall - i64::from(clock.offset_at(guess))
}

impl Field {
    fn parse(&self, text: &str) -> Result<(u64, bool), CronError> {
        if text == "*" || text == "?" {
            return Ok((self.span(self.min, self.max, 1), true));
        }
        let mut set = 0;
        for part in text.split(',') {
            let (span, step_text) = match part.split_once('/') {
                Some((span, step)) => (span, Some(step)),
                None => (part, None),
            };
            let step = match step_text {
                Some(step) => step
                    .parse::<u32>()
                    .ok()
                    .filter(|n| *n > 0)
                    .ok_or_else(|| CronError(format!("invalid step in {}", quote(part))))?,
                None => 1,
            };
            let (mut low, mut high) = (self.min, self.max);
            if span != "*" && span != "?" {
                let (from, to) = match span.split_once('-') {
                    Some((from, to)) => (from, Some(to)),
                    None => (span, None),
                };
                low = self.value(from)?;
                high = match to {
                    Some(to) => self.value(to)?,
                    None if step_text.is_some() => self.max,
                    None => low,
                };
            }
            if low > high {
                return Err(CronError(format!("invalid range {}", quote(part))));
            }
            set |= self.span(low, high, step);
        }
        Ok((set, false))
    }

    fn value(&self, text: &str) -> Result<u32, CronError> {
        let lower = text.to_ascii_lowercase();
        if let Some((_, value)) = self.names.iter().find(|(name, _)| *name == lower) {
            return Ok(*value);
        }
        text.parse::<u32>()
            .ok()
            .filter(|value| (self.min..=self.max).contains(value))
            .ok_or_else(|| {
                CronError(format!(
                    "{} is not between {} and {}",
                    quote(text),
                    self.min,
                    self.max
                ))
            })
    }

    fn span(&self, low: u32, high: u32, step: u32) -> u64 {
        (low..=high)
            .step_by(step as usize)
            .fold(0, |set, value| set | 1u64 << value)
    }
}

#[cfg(test)]
mod tests {
    use time::macros::datetime;

    use super::*;

    struct Fixed(i32);

    impl LocalClock for Fixed {
        fn offset_at(&self, _unix: i64) -> i32 {
            self.0
        }
    }

    struct UsEastern;

    impl UsEastern {
        fn nth_sunday(year: i32, month: Month, nth: u8, hour_utc: u8) -> i64 {
            let first = Date::from_calendar_date(year, month, 1).unwrap();
            let to_sunday = (7 - first.weekday().number_days_from_sunday()) % 7;
            let day = 1 + to_sunday + 7 * (nth - 1);
            let date = Date::from_calendar_date(year, month, day).unwrap();
            date.with_hms(hour_utc, 0, 0)
                .unwrap()
                .assume_utc()
                .unix_timestamp()
        }
    }

    impl LocalClock for UsEastern {
        fn offset_at(&self, unix: i64) -> i32 {
            let year = OffsetDateTime::from_unix_timestamp(unix).unwrap().year();
            let start = Self::nth_sunday(year, Month::March, 2, 7);
            let end = Self::nth_sunday(year, Month::November, 1, 6);
            if (start..end).contains(&unix) {
                -4 * 3600
            } else {
                -5 * 3600
            }
        }
    }

    fn at(clock: &dyn LocalClock, text: &str) -> i64 {
        let format =
            time::macros::format_description!("[year]-[month]-[day] [hour]:[minute]:[second]");
        let wall = time::PrimitiveDateTime::parse(text, &format)
            .unwrap()
            .assume_utc()
            .unix_timestamp();
        let guess = wall - i64::from(clock.offset_at(wall));
        wall - i64::from(clock.offset_at(guess))
    }

    #[test]
    fn next_follows_the_local_clock() {
        let shanghai = Fixed(8 * 3600);
        let kolkata = Fixed(5 * 3600 + 1800);
        let cases: [(&str, &dyn LocalClock, &str, &str); 12] = [
            (
                "0 8 * * *",
                &shanghai,
                "2026-10-25 07:59:59",
                "2026-10-25 08:00:00",
            ),
            (
                "0 8 * * *",
                &shanghai,
                "2026-10-25 08:00:00",
                "2026-10-26 08:00:00",
            ),
            (
                "*/10 * * * *",
                &shanghai,
                "2026-10-25 08:05:30",
                "2026-10-25 08:10:00",
            ),
            (
                "0 5,17 * * *",
                &shanghai,
                "2026-10-25 05:00:00",
                "2026-10-25 17:00:00",
            ),
            (
                "0 17 * * sun",
                &shanghai,
                "2026-10-26 00:00:00",
                "2026-11-01 17:00:00",
            ),
            (
                "0 0 1 jan-mar/2 *",
                &shanghai,
                "2026-01-02 00:00:00",
                "2026-03-01 00:00:00",
            ),
            (
                "30 */2 * * * *",
                &shanghai,
                "2026-10-25 08:00:31",
                "2026-10-25 08:02:30",
            ),
            (
                "0 0 13 * 5",
                &shanghai,
                "2026-10-25 00:00:00",
                "2026-10-30 00:00:00",
            ),
            (
                "0 0 * * 7",
                &shanghai,
                "2026-10-25 00:00:00",
                "2026-11-01 00:00:00",
            ),
            (
                "0 9 * * *",
                &kolkata,
                "2026-10-25 09:30:00",
                "2026-10-26 09:00:00",
            ),
            (
                "30 2 * * *",
                &UsEastern,
                "2026-03-08 00:00:00",
                "2026-03-09 02:30:00",
            ),
            (
                "30 1 * * *",
                &UsEastern,
                "2026-11-01 01:30:00",
                "2026-11-02 01:30:00",
            ),
        ];
        for (expression, clock, from, want) in cases {
            let schedule = CronSchedule::parse(expression).unwrap();
            let from = at(clock, from);
            let got = schedule.next(from, clock).unwrap();
            assert_eq!(got, at(clock, want), "{expression} after {from}");
            assert!(got > from);
        }
        assert!(
            CronSchedule::parse("0 0 30 2 *")
                .unwrap()
                .next(0, &UtcClock)
                .is_none()
        );
    }

    #[test]
    fn keeps_going_forward_through_a_repeated_hour() {
        let schedule = CronSchedule::parse("* 59 1 * * *").unwrap();
        let first_pass = datetime!(2026-11-01 5:59:59 UTC).unix_timestamp();
        let next = schedule.next(first_pass, &UsEastern).unwrap();
        assert!(next - first_pass >= 59 * 60, "{}", next - first_pass);
    }

    #[test]
    fn rejects_bad_expressions() {
        for expression in [
            "* * * *",
            "60 * * * *",
            "* 24 * * *",
            "* * 0 * *",
            "* * * 13 *",
            "* * * * 8",
            "*/0 * * * *",
            "5-1 * * * *",
            "* * * * mon-xyz",
        ] {
            assert!(CronSchedule::parse(expression).is_err(), "{expression}");
        }
    }
}
