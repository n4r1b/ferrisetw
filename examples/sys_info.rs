use ferrisetw::query::*;

fn main() {
    println!("Max PMC: {}", SessionlessInfo::max_pmc().unwrap());
    println!(
        "Profile Interval: {}",
        SessionlessInfo::sample_interval(ProfileSource::ProfileTime).unwrap()
    );

    let sources = SessionlessInfo::profile_sources().unwrap();
    println!("Profile Sources:");
    for source in sources {
        println!(
            "  {:<32}: {:02} [{}-{}]",
            source.description, source.id, source.min_interval, source.max_interval
        );
    }
}
