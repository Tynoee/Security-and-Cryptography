def read_file(path):
    with open(path, 'r') as file:
        return file.read()

def write_file(filepath, content):
    with open(filepath, "w", encoding="utf-8") as file:
        file.write(content)
