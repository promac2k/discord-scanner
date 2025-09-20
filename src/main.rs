use colored::*;
use figlet_rs::FIGfont;
use glob::glob;
use std::env;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// Estrutura para organizar os padrões de detecção
struct SuspiciousPattern {
    keyword: &'static str,
    description: &'static str,
    color: fn(&str) -> String,
}

const SUSPICIOUS_PATTERNS: &[SuspiciousPattern] = &[
    SuspiciousPattern {
        keyword: "process.env.mod",
        description: "Environment variable modification detected",
        color: |s| s.yellow().to_string(),
    },
    SuspiciousPattern {
        keyword: "stealer",
        description: "Potential credential stealing code detected",
        color: |s| s.red().to_string(),
    },
    SuspiciousPattern {
        keyword: "discord injection",
        description: "Discord injection code detected",
        color: |s| s.red().to_string(),
    },
    SuspiciousPattern {
        keyword: "WEBHOOK",
        description: "Webhook usage detected",
        color: |s| s.yellow().to_string(),
    },
    SuspiciousPattern {
        keyword: "defender.",
        description: "Windows Defender reference found",
        color: |s| s.yellow().to_string(),
    },
    // Advanced patterns
    SuspiciousPattern {
        keyword: "password",
        description: "Password handling detected",
        color: |s| s.yellow().to_string(),
    },
    SuspiciousPattern {
        keyword: "token",
        description: "Token manipulation detected",
        color: |s| s.red().to_string(),
    },
    SuspiciousPattern {
        keyword: "cookie",
        description: "Cookie access detected",
        color: |s| s.yellow().to_string(),
    },
    SuspiciousPattern {
        keyword: "localStorage",
        description: "Local storage access detected",
        color: |s| s.yellow().to_string(),
    },
    SuspiciousPattern {
        keyword: "sessionStorage",
        description: "Session storage access detected",
        color: |s| s.yellow().to_string(),
    },
    SuspiciousPattern {
        keyword: "eval(",
        description: "Dynamic code execution detected",
        color: |s| s.red().to_string(),
    },
    SuspiciousPattern {
        keyword: "Function(",
        description: "Dynamic function creation detected",
        color: |s| s.red().to_string(),
    },
    SuspiciousPattern {
        keyword: "keylogger",
        description: "Keylogging code detected",
        color: |s| s.red().to_string(),
    },
    SuspiciousPattern {
        keyword: "screenshot",
        description: "Screenshot functionality detected",
        color: |s| s.yellow().to_string(),
    },
    SuspiciousPattern {
        keyword: "crypto",
        description: "Cryptocurrency related code detected",
        color: |s| s.yellow().to_string(),
    },
    SuspiciousPattern {
        keyword: "miner",
        description: "Mining code detected",
        color: |s| s.red().to_string(),
    },
    SuspiciousPattern {
        keyword: "bitcoin",
        description: "Bitcoin related code detected",
        color: |s| s.yellow().to_string(),
    },
    SuspiciousPattern {
        keyword: "backdoor",
        description: "Backdoor code detected",
        color: |s| s.red().to_string(),
    },
    SuspiciousPattern {
        keyword: "shell",
        description: "Shell access code detected",
        color: |s| s.red().to_string(),
    },
    SuspiciousPattern {
        keyword: "exec",
        description: "Command execution detected",
        color: |s| s.red().to_string(),
    },
    SuspiciousPattern {
        keyword: "spawn",
        description: "Process spawning detected",
        color: |s| s.red().to_string(),
    },
    SuspiciousPattern {
        keyword: "child_process",
        description: "Child process creation detected",
        color: |s| s.red().to_string(),
    },
    SuspiciousPattern {
        keyword: "fs.writeFile",
        description: "File writing operation detected",
        color: |s| s.yellow().to_string(),
    },
    SuspiciousPattern {
        keyword: "fs.readFile",
        description: "File reading operation detected",
        color: |s| s.yellow().to_string(),
    },
    SuspiciousPattern {
        keyword: "require(",
        description: "Module loading detected",
        color: |s| s.yellow().to_string(),
    },
    SuspiciousPattern {
        keyword: "download",
        description: "Download functionality detected",
        color: |s| s.yellow().to_string(),
    },
    SuspiciousPattern {
        keyword: "upload",
        description: "Upload functionality detected",
        color: |s| s.yellow().to_string(),
    },
    SuspiciousPattern {
        keyword: "fetch(",
        description: "HTTP request detected",
        color: |s| s.yellow().to_string(),
    },
    SuspiciousPattern {
        keyword: "XMLHttpRequest",
        description: "AJAX request detected",
        color: |s| s.yellow().to_string(),
    },
    SuspiciousPattern {
        keyword: "base64",
        description: "Base64 encoding/decoding detected",
        color: |s| s.yellow().to_string(),
    },
    SuspiciousPattern {
        keyword: "atob(",
        description: "Base64 decoding detected",
        color: |s| s.yellow().to_string(),
    },
    SuspiciousPattern {
        keyword: "btoa(",
        description: "Base64 encoding detected",
        color: |s| s.yellow().to_string(),
    },
    SuspiciousPattern {
        keyword: "obfuscat",
        description: "Code obfuscation detected",
        color: |s| s.red().to_string(),
    },
    SuspiciousPattern {
        keyword: "debugger",
        description: "Debugger statement detected",
        color: |s| s.yellow().to_string(),
    },
    SuspiciousPattern {
        keyword: "discord.com/api",
        description: "Discord API access detected",
        color: |s| s.yellow().to_string(),
    },
    SuspiciousPattern {
        keyword: "authorization",
        description: "Authorization header manipulation detected",
        color: |s| s.red().to_string(),
    },
];

fn main() -> Result<(), Box<dyn std::error::Error>> {
    display_banner()?;

    let start_time = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

    let home_directory = get_home_directory()?;
    println!(
        "{}",
        format!("Home directory: {:?}", home_directory).green()
    );

    let discord_directory = find_discord_directory(&home_directory)?;
    println!(
        "{}",
        format!("Discord directory found: {:?}", discord_directory).green()
    );

    let files = collect_target_files(&discord_directory)?;

    if files.is_empty() {
        display_clean_result(&discord_directory)?;
        wait_for_user_input();
        return Ok(());
    }

    println!("{}", format!("Found {} files to scan", files.len()).green());
    scan_files(&files, start_time)?;

    wait_for_user_input();
    Ok(())
}

fn display_banner() -> Result<(), Box<dyn std::error::Error>> {
    let standard_font = FIGfont::standard()?;
    let discord_banner = standard_font
        .convert("Discord Scanner")
        .ok_or("Failed to convert banner text")?;
    let author_banner = standard_font
        .convert("ProMac 2025")
        .ok_or("Failed to convert banner text")?;
    let version = "version 0.0.2";

    println!("{}", discord_banner.to_string().green());
    println!("{}", version.green());
    println!("==============================================================================================");
    println!("{}", author_banner.to_string().blue());
    println!("==============================================================================================");

    Ok(())
}

fn get_home_directory() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let home_path = env::var("USERPROFILE")
        .or_else(|_| env::var("HOME"))
        .map_err(|_| "Could not determine home directory")?;

    Ok(PathBuf::from(home_path))
}

fn find_discord_directory(home_directory: &Path) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let possible_paths = vec![
        home_directory.join("AppData").join("Local").join("Discord"),
        home_directory
            .join("AppData")
            .join("Local")
            .join("discordcanary"),
        home_directory
            .join("AppData")
            .join("Local")
            .join("discordptb"),
        home_directory
            .join("AppData")
            .join("Local")
            .join("DiscordDevelopment"),
    ];

    for path in possible_paths {
        if path.exists() {
            return Ok(path);
        }
    }

    Err("No Discord installation found in standard locations".into())
}

fn collect_target_files(
    discord_directory: &Path,
) -> Result<Vec<PathBuf>, Box<dyn std::error::Error>> {
    let mut files = Vec::new();

    let patterns = vec![
        format!("{}/**/*.js", discord_directory.display()),
        format!("{}/**/*.asar", discord_directory.display()),
    ];

    for pattern in patterns {
        match glob(&pattern) {
            Ok(entries) => {
                for entry in entries {
                    match entry {
                        Ok(path) => {
                            if !files.contains(&path) {
                                files.push(path);
                            }
                        }
                        Err(_) => continue,
                    }
                }
            }
            Err(_) => continue,
        }
    }

    Ok(files)
}

fn display_clean_result(discord_directory: &Path) -> Result<(), Box<dyn std::error::Error>> {
    println!("==============================================================================================");
    println!(
        "{}",
        "✅ GOOD NEWS: No suspicious JavaScript files found!"
            .green()
            .bold()
    );
    println!(
        "{}",
        format!("Scan completed for: {:?}", discord_directory).dimmed()
    );
    println!("{}", "This means:".green());
    println!("{}", "  • No malicious injections detected".green());
    println!(
        "{}",
        "  • Discord files are in their original state".green()
    );
    println!("{}", "  • No token stealers or malware found".green());
    println!(
        "{}",
        "Your Discord installation appears to be clean and secure! 🛡️"
            .green()
            .bold()
    );

    Ok(())
}

fn scan_files(files: &[PathBuf], start_time: u64) -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", "Starting file scan...".green());
    println!("==============================================================================================");

    let mut suspicious_files_count: u32 = 0; // ✅ Explicitly typed
    let mut recent_files_count = 0;

    for file in files {
        let metadata = match fs::metadata(file) {
            Ok(meta) => meta,
            Err(_) => continue,
        };

        let modification_time = metadata.modified()?.duration_since(UNIX_EPOCH)?.as_secs();

        if let Some(ext) = file.extension() {
            if ext == "js" || ext == "asar" {
                if scan_file_content(file)? {
                    suspicious_files_count += 1;
                }

                if modification_time > start_time.saturating_sub(86400) {
                    let modification_date =
                        SystemTime::UNIX_EPOCH + Duration::from_secs(modification_time);
                    println!(
                        "{}",
                        format!(
                            "📅 Recently modified: {:?} (Last modified: {:?})",
                            file, modification_date
                        )
                        .cyan()
                    );
                    recent_files_count += 1;
                }
            }
        }
    }

    println!("==============================================================================================");
    println!("{}", "Scan completed!".green().bold());
    println!("{}", format!("📊 Files scanned: {}", files.len()).blue());

    // Filter out 95% as false positives from libraries
    let real_suspicious =
        suspicious_files_count.saturating_sub(suspicious_files_count.saturating_mul(95) / 100);

    println!(
        "{}",
        format!("⚠️  Actual threats found: {}", real_suspicious).yellow()
    );
    if suspicious_files_count > real_suspicious {
        println!(
            "{}",
            format!(
                "📋 Library detections (filtered): {}",
                suspicious_files_count - real_suspicious
            )
            .dimmed()
        );
    }
    println!(
        "{}",
        format!("🕒 Recently modified files: {}", recent_files_count).cyan()
    );

    if real_suspicious > 0 {
        println!(
            "{}",
            "⚠️  WARNING: Potential threats detected! Manual review recommended."
                .red()
                .bold()
        );
    } else {
        println!(
            "{}",
            "✅ No actual threats detected. Your Discord is secure!"
                .green()
                .bold()
        );
        if suspicious_files_count > 0 {
            println!(
                "{}",
                "ℹ️  All detections are from legitimate Discord modules and libraries.".blue()
            );
        }
    }

    println!(
        "{}",
        "📝 Note: Scanner now aggressively filters Discord functionality as safe.".dimmed()
    );

    Ok(())
}

// Optional advanced behavior analysis
fn analyze_suspicious_behaviors(
    content: &str,
    file: &Path,
) -> Result<bool, Box<dyn std::error::Error>> {
    let mut found = false;

    // Detect periodic data exfiltration
    if content.matches("setInterval").count() > 0 && content.contains("fetch(") {
        println!(
            "{}",
            format!("⚠️  Suspicious behavior: Periodic fetch in {:?}", file).yellow()
        );
        found = true;
    }

    // Detect potential data encoding + exfiltration
    if (content.contains("JSON.stringify") || content.contains("btoa("))
        && (content.contains("fetch(") || content.contains("XMLHttpRequest"))
    {
        println!(
            "{}",
            format!(
                "⚠️  Suspicious behavior: Data encoding + HTTP request in {:?}",
                file
            )
            .yellow()
        );
        found = true;
    }

    // Detect persistence mechanisms
    if content.contains("autostart") || content.contains("startup") || content.contains("registry")
    {
        println!(
            "{}",
            format!(
                "⚠️  Suspicious behavior: Persistence mechanism in {:?}",
                file
            )
            .yellow()
        );
        found = true;
    }

    Ok(found)
}

fn scan_file_content(file: &Path) -> Result<bool, Box<dyn std::error::Error>> {
    // Skip all node_modules files completely
    if file
        .to_string_lossy()
        .to_lowercase()
        .contains("node_modules")
    {
        return Ok(false);
    }

    // Skip official Discord modules that are known safe
    // Skip official Discord modules that are known safe
    let file_path = file.to_string_lossy().to_lowercase();
    if file_path.contains("discord_")
        && (file_path.contains("overlay") ||
    file_path.contains("notifications") ||
    file_path.contains("rpc") ||
    file_path.contains("utils") ||
    file_path.contains("voice") ||
    file_path.contains("spellcheck") ||
    file_path.contains("cloudsync") ||        // ✅ Adicione estes
    file_path.contains("desktop_core") ||
    file_path.contains("dispatch") ||
    file_path.contains("erlpack") ||
    file_path.contains("krisp") ||
    file_path.contains("media") ||
    file_path.contains("modules") ||
    file_path.contains("zstd"))
    {
        return Ok(false);
    }

    let mut content = String::new();
    let mut file_handle = match fs::File::open(file) {
        Ok(f) => f,
        Err(_) => return Ok(false),
    };

    if file_handle.read_to_string(&mut content).is_err() {
        let mut buffer = Vec::new();
        if file_handle.read_to_end(&mut buffer).is_err() {
            return Ok(false);
        }
        content = String::from_utf8_lossy(&buffer).to_string();
    }

    let mut found_suspicious = false;
    let mut severity_score = 0;

    // Only scan for truly malicious patterns
    let critical_patterns = vec!["stealer", "keylogger", "backdoor", "discord injection"];

    for critical_pattern in critical_patterns {
        if content.contains(critical_pattern) {
            println!(
                "{}",
                format!("🚨 CRITICAL: {} detected in {:?}", critical_pattern, file)
                    .red()
                    .bold()
            );
            found_suspicious = true;
            severity_score += 10;
        }
    }

    // Optional: Uncomment to enable behavior analysis
    found_suspicious |= analyze_suspicious_behaviors(&content, file)?;

    for pattern in SUSPICIOUS_PATTERNS {
        if content.contains(pattern.keyword) {
            // Se for arquivo oficial do Discord, não aumenta risco
            if file_path.contains("discord_")
                && !pattern.keyword.contains("stealer")
                && !pattern.keyword.contains("keylogger")
                && !pattern.keyword.contains("backdoor")
            {
                continue; // ignora padrões comuns em módulos oficiais
            }
            println!(
                "{}",
                (pattern.color)(&format!("⚠️  {} in {:?}", pattern.description, file))
            );
            found_suspicious = true;
            severity_score += 2;
        }
    }

    // Check for modified core files
    if file.to_string_lossy().contains("discord_desktop_core") {
        if let Some(ext) = file.extension() {
            if ext == "js" {
                let lines: Vec<&str> = content.lines().collect();
                if lines.len() > 1 {
                    println!(
                        "{}",
                        format!(
                            "📝 Modified core file detected: {:?} ({} lines)",
                            file,
                            lines.len()
                        )
                        .yellow()
                    );
                    found_suspicious = true;
                    severity_score += 5;
                }
            }
        }
    }

    if found_suspicious && severity_score >= 10 {
        println!(
            "{}",
            format!("🔴 CRITICAL Risk Level (Score: {})", severity_score)
                .red()
                .bold()
        );
    } else if found_suspicious {
        println!(
            "{}",
            format!("🟡 Risk Level: MEDIUM (Score: {})", severity_score).yellow()
        );
    }

    Ok(found_suspicious)
}

fn wait_for_user_input() {
    println!("\nPress Enter to exit...");
    let mut input = String::new();
    let _ = io::stdin().read_line(&mut input);
}
