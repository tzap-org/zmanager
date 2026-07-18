import re

with open("crates/zmanager-cli/src/app.rs", "r") as f:
    content = f.read()

# Add the take_value_or_exit helper right after take_value
helper = """fn take_value_or_exit(args: &[String], index: &mut usize, option: &str) -> String {
    take_value(args, index, option).unwrap_or_else(|e| {
        eprintln!("{}", e);
        std::process::exit(1);
    })
}
"""

# Find fn take_value
idx = content.find("fn take_value(args: &[String], index: &mut usize, option: &str) -> Result<String, String> {")
content = content[:idx] + helper + "\n" + content[idx:]

# Replace take_value(...).unwrap() with take_value_or_exit(...)
content = re.sub(r'take_value\(([^)]+)\)\.unwrap\(\)', r'take_value_or_exit(\1)', content)

with open("crates/zmanager-cli/src/app.rs", "w") as f:
    f.write(content)

