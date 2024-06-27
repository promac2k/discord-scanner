use std::env;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH, Duration};
use std::io::{self, Read};
use colored::*;
use glob::glob;
use figlet_rs::FIGfont;

fn main() {

    // Create the ASCII banners
    let standard_font = FIGfont::standard().unwrap();
    let discord_banner = standard_font.convert("Discord Scanner").unwrap();
    let author_banner = standard_font.convert("ProMac 2024").unwrap();
    let version = "version 0.0.1";

    println!("{}", discord_banner.to_string().green());
    println!("{}", version.to_string().green());
    println!("==============================================================================================");
    println!("{}", author_banner.to_string().blue());

    let start_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

    // Get the user's home directory
    let home_directory = match env::var("USERPROFILE").or_else(|_| env::var("HOME")) {
        Ok(path) => PathBuf::from(path),
        Err(_) => {
            eprintln!("{}", "Could not determine home directory".red());
            return;
        }
    };
    println!("{}", format!("Home directory: {:?}", home_directory).green());

    // Construct the Discord directory path
    let discord_directory = home_directory.join("AppData").join("Local").join("Discord");

    // Check if discord directory exists
    let discord_directory = if discord_directory.exists() {
        discord_directory
    } else {
        println!("{}", format!("Discord directory not found at {:?}", discord_directory).red());
        let discord_canary_directory = home_directory.join("AppData").join("Local").join("discordcanary");
        if discord_canary_directory.exists() {
            discord_canary_directory
        } else {
            println!("{}", format!("Discord canary directory not found at {:?}", discord_canary_directory).red());
            println!("Press enter to exit...");
            let mut input = String::new();
            io::stdin().read_line(&mut input).unwrap();
            return;
        }
    };

    // Update the glob pattern to include .asar files
    let pattern = format!("{}/**/*.{{js,asar}}", discord_directory.to_str().unwrap());
    let mut all_files = Vec::new();

    for entry in glob(&pattern).expect("Failed to read glob pattern") {
        match entry {
            Ok(path) => all_files.push(path),
            Err(e) => eprintln!("{:?}", e),
        }
    }

    println!("{}", format!("Searching for last changed JavaScript files in {:?}", discord_directory).green());
    println!("{}", format!("Searching for 'injection code words' in .js and .asar files in {:?}", discord_directory).green());
    println!("==============================================================================================");

    for file in all_files {
        let metadata = fs::metadata(&file).unwrap();
        let modification_time = metadata.modified().unwrap().duration_since(UNIX_EPOCH).unwrap().as_secs();

        // Check if the file contains any possible injection code words
        if file.extension().map_or(false, |ext| ext == "js" || ext == "asar") {
            let mut content = String::new();
            if let Ok(mut f) = fs::File::open(&file) {
                f.read_to_string(&mut content).unwrap();
            }

            if content.contains("process.env.mod") && file.to_string_lossy().contains("discord_desktop_core") {
                println!("{}", format!("'process.env' is being used, code found in {:?}", file).yellow());
            }
            if content.contains("stealer") {
                println!("{}", format!("'steal' is being used, code found in {:?}", file).yellow());
            }
            if content.contains("/cdn.") && content.contains("http") {
                println!("{}", format!("'cdn' is being used, code found in {:?}", file).yellow());
            }
            if content.contains("discord injection") {
                println!("{}", format!("Injection code found in {:?}", file).yellow());
            }
            if content.contains("WEBHOOK") {
                println!("{}", format!("WEBHOOK found in {:?}", file).yellow());
            }
            if content.contains("defender.") {
                println!("{}", format!("'defender.' found in {:?}", file).yellow());
            }
            if file.to_string_lossy().contains("discord_desktop_core") && file.extension().map_or(false, |ext| ext == "js") {
                let lines: Vec<&str> = content.lines().collect();
                if lines.len() > 1 {
                    println!("{}", format!("More than one line found in {:?}", file).yellow());
                }
            }
        }

        // Check if the file was modified within the last 24 hours
        if (file.extension().map_or(false, |ext| ext == "js" || ext == "asar")) && modification_time > start_time - 86400 {
            println!("{}", format!("{:?}: Last modified on {:?}", file, SystemTime::UNIX_EPOCH + Duration::from_secs(modification_time)).green());
        }
    }

    println!("Press enter to exit...");
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
}
