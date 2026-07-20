use std::{
    collections::{HashMap, HashSet},
    fs,
    path::Path,
};

use anyhow::{Context, Result, bail};

use crate::{config::Scope, error::FlowtopError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessIdentity {
    pub pid: u32,
    pub ppid: u32,
    pub start_time_ticks: u64,
    pub comm: String,
    pub cpu_ticks: u64,
}

pub fn parse_proc_stat(pid: u32, input: &str) -> Result<ProcessIdentity> {
    let open = input.find('(').context("missing process name")?;
    let close = input
        .rfind(')')
        .context("missing process name terminator")?;
    let comm = input[open + 1..close].to_owned();
    let fields: Vec<&str> = input[close + 1..].split_whitespace().collect();
    if fields.len() < 20 {
        bail!("short /proc/{pid}/stat record");
    }
    let ppid = fields[1].parse().context("invalid ppid")?;
    let user_ticks: u64 = fields[11].parse().context("invalid utime")?;
    let system_ticks: u64 = fields[12].parse().context("invalid stime")?;
    let start_time_ticks = fields[19].parse().context("invalid starttime")?;
    Ok(ProcessIdentity {
        pid,
        ppid,
        start_time_ticks,
        comm,
        cpu_ticks: user_ticks.saturating_add(system_ticks),
    })
}

pub fn scan_processes(proc_root: &Path) -> Result<Vec<ProcessIdentity>> {
    let mut processes = Vec::new();
    for entry in fs::read_dir(proc_root).context("read /proc")? {
        let Ok(entry) = entry else { continue };
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse().ok())
        else {
            continue;
        };
        let Ok(stat) = fs::read_to_string(entry.path().join("stat")) else {
            continue;
        };
        if let Ok(identity) = parse_proc_stat(pid, &stat) {
            processes.push(identity);
        }
    }
    Ok(processes)
}

pub fn resolve_pids(
    proc_root: &Path,
    scope: &Scope,
    include_children: bool,
) -> Result<Vec<ProcessIdentity>> {
    if matches!(scope, Scope::Host) {
        return Ok(Vec::new());
    }
    let processes = scan_processes(proc_root)?;
    let mut selected: HashSet<u32> = match scope {
        Scope::Pid(pid) => {
            if !processes.iter().any(|process| process.pid == *pid) {
                return Err(FlowtopError::PidNotFound(*pid).into());
            }
            HashSet::from([*pid])
        }
        Scope::Process(name) => processes
            .iter()
            .filter(|process| process.comm == *name)
            .map(|process| process.pid)
            .collect(),
        Scope::Host => unreachable!(),
    };

    if include_children {
        loop {
            let before = selected.len();
            for process in &processes {
                if selected.contains(&process.ppid) {
                    selected.insert(process.pid);
                }
            }
            if selected.len() == before {
                break;
            }
        }
    }

    Ok(processes
        .into_iter()
        .filter(|process| selected.contains(&process.pid))
        .collect())
}

pub fn socket_inodes(proc_root: &Path, pids: &[ProcessIdentity]) -> HashSet<u64> {
    let mut inodes = HashSet::new();
    for process in pids {
        let fd_dir = proc_root.join(process.pid.to_string()).join("fd");
        let Ok(entries) = fs::read_dir(fd_dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(target) = fs::read_link(entry.path()) else {
                continue;
            };
            let target = target.to_string_lossy();
            if let Some(value) = target
                .strip_prefix("socket:[")
                .and_then(|value| value.strip_suffix(']'))
                .and_then(|value| value.parse().ok())
            {
                inodes.insert(value);
            }
        }
    }
    inodes
}

pub fn process_io_totals(proc_root: &Path, pids: &[ProcessIdentity]) -> (u64, u64) {
    let mut read = 0_u64;
    let mut write = 0_u64;
    for process in pids {
        let Ok(contents) = fs::read_to_string(proc_root.join(process.pid.to_string()).join("io"))
        else {
            continue;
        };
        let fields: HashMap<&str, u64> = contents
            .lines()
            .filter_map(|line| {
                let (key, value) = line.split_once(':')?;
                Some((key, value.trim().parse().ok()?))
            })
            .collect();
        read = read.saturating_add(fields.get("read_bytes").copied().unwrap_or(0));
        write = write.saturating_add(fields.get("write_bytes").copied().unwrap_or(0));
    }
    (read, write)
}

pub fn process_rss_bytes(proc_root: &Path, pids: &[ProcessIdentity]) -> Option<u64> {
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if page_size <= 0 {
        return None;
    }
    let mut total = 0_u64;
    let mut found = false;
    for process in pids {
        let Ok(statm) = fs::read_to_string(proc_root.join(process.pid.to_string()).join("statm"))
        else {
            continue;
        };
        let Some(pages) = statm
            .split_whitespace()
            .nth(1)
            .and_then(|value| value.parse::<u64>().ok())
        else {
            continue;
        };
        found = true;
        total = total.saturating_add(pages.saturating_mul(page_size as u64));
    }
    found.then_some(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_comm_with_spaces_and_parentheses() {
        let input = "42 (worker (blue)) S 1 0 0 0 0 0 0 0 0 0 10 5 0 0 20 0 1 0 1234 0";
        let process = parse_proc_stat(42, input).unwrap();
        assert_eq!(process.comm, "worker (blue)");
        assert_eq!(process.ppid, 1);
        assert_eq!(process.cpu_ticks, 15);
        assert_eq!(process.start_time_ticks, 1234);
    }
}
