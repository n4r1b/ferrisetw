use ferrisetw::query::*;

fn main() {
    println!("Max PMC: {}", SessionlessInfo::max_pmc().unwrap());
    println!(
        "Profile Interval: {}",
        SessionlessInfo::sample_interval(ProfileSource::ProfileTime).unwrap()
    );
}
