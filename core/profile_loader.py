def load_profile(profile_name):
    path = f"profiles/{profile_name}.yaml"
    modules = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                s = line.strip()
                if s.startswith("- "):
                    modules.append(s[2:].strip())
        return modules
    except FileNotFoundError:
        print(f"[!] Profile not found: {path}")
        return []
