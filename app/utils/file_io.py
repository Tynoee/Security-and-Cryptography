def read_file(filepath):
    with open(filepath, "r", encoding="utf-8") as file:
        return file.read()

def write_file(filepath, content):
    with open(filepath, "w", encoding="utf-8") as file:
        file.write(content)
