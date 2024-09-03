import sys
import re
import urllib.parse

def validate_whitespace(map_string):
    # Patterns to detect invalid whitespace within the map string, but exclude simple strings
    invalid_patterns = [
        r'\(\s',  # Space after opening parenthesis
        r'\s\)',  # Space before closing parenthesis
        r':[^\s]*\s+[^\s]*:',  # Space between keys/values
        r'\(<\s',  # Space after opening angle bracket
        r'\s>\)',  # Space before closing angle bracket
        r'[^\s]*\s+[^\s]*>',  # Space before closing angle bracket
        r'[^\s]*\s+[^\s]*<',  # Space before opening angle bracket
        r'[a-z]+\s+[a-z]+:',  # Space within keys
        r'[^\s]*:[^\s]+s[^<]*',  # Improper spaces in simple strings
    ]
    
    for pattern in invalid_patterns:
        if re.search(pattern, map_string):
            sys.stderr.write(f"ERROR -- Invalid whitespace found in map: {map_string}\n")
            exit(66)

def parse_file(file_data):
    # Parses the input data and recursively handles nested maps, converting them to a formatted string output.
    result_output = "begin-map\n"
    for key, value in parse_content(file_data).items():
        if is_empty_map(key, value):
            result_output += ""
        elif is_valid_key(key):
            if is_map(value):
                result_output += f"{key} -- map -- \n"
                result_output += parse_file(value)
            elif is_binary_number(value):
                parsed_number = decode_binary_number(value)
                result_output += f"{key} -- num -- {parsed_number}\n"
            elif is_complex_string(value):
                decoded_string = decode_complex_string(value)
                result_output += f"{key} -- string -- {decoded_string}\n"
            elif is_simple_string(value):
                decoded_string = decode_simple_string(value)
                result_output += f"{key} -- string -- {decoded_string}\n"
            else:
                sys.stderr.write(f"ERROR -- Invalid data format with key: {key} and value: {value}\n")
                exit(66)
        else:
            sys.stderr.write(f"ERROR -- Invalid key found: {key}\n")
            exit(66)
    result_output += "end-map\n"
    return result_output

def is_valid_key(key):
    # Checks if the given key is valid (lowercase alphabetic characters only).
    pattern = r'^[a-z]+$'
    return bool(re.match(pattern, key))

def is_binary_number(num):
    # Checks if the given value is a binary number (only contains 0 and 1).
    pattern = r'^[01]+$'
    return bool(re.match(pattern, num))

def decode_binary_number(binary_value):
    # Decodes a binary number, accounting for two's complement if necessary.
    if binary_value[0] == '1':
        num_bits = len(binary_value)
        value = int(binary_value, 2) - (1 << num_bits)
    else:
        value = int(binary_value, 2)
    return value

def is_simple_string(simple_string):
    # Checks if the given value is a valid simple string (ends with 's' and may contain escaped sequences).
    pattern = r'^[a-zA-Z0-9\s\\t\\n%]*s$'
    return bool(re.match(pattern, simple_string))

def decode_simple_string(simple_string):
    # Decodes a simple string by replacing escape sequences with their actual characters.
    decoded = simple_string[:-1].replace("\\t", "\t").replace("\\n", "\n")
    return decoded

def decode_complex_string(complex_string):
    # Decodes a complex string by unquoting percent-encoded sequences.
    return urllib.parse.unquote(complex_string)

def is_map(map_string):
    # Checks if the given value is a valid map (enclosed in parentheses and angle brackets).
    pattern = r'^\(<.*>\)$'
    return bool(re.match(pattern, map_string))

def is_complex_string(complex_string):
    # Checks if the given value is a complex string (contains percent-encoded sequences).
    pattern = r'%[0-9A-Fa-f]{2}'
    return bool(re.search(pattern, complex_string))

def parse_content(file_data):
    # Parses the map content and returns a dictionary of key-value pairs.
    if not is_map(file_data):
        sys.stderr.write(f"ERROR -- Invalid value found: {file_data}\n")
        exit(66)
    content_dict = {}
    stripped_map = re.sub(r'^\(<(.*)>\)$', r'\1', file_data)
   
    # Check if there's a trailing comma after stripping
    if stripped_map.endswith(','):
        sys.stderr.write(f"ERROR -- Trailing comma found in input: {file_data}\n")
        exit(66)
   
    if ',' in stripped_map:
        return parse_comma_separated_pairs(stripped_map)
    if stripped_map == "":
        content_dict[""] = stripped_map
    else:
        key_value_pairs = stripped_map.split(':', 1)
        if len(key_value_pairs) != 2:
            sys.stderr.write(f"ERROR -- Invalid value map formatting found\n")
            exit(66)
        content_dict[key_value_pairs[0]] = key_value_pairs[1]
    return content_dict
   
def parse_comma_separated_pairs(stripped_map):
    # Parses comma-separated key-value pairs within a map and handles nested maps.
    comma_separated_content = {}
    key_value_pairs = split_by_comma_but_keep_maps(stripped_map)
    unique_keys = set()
    for pair in key_value_pairs:
        if pair == "" or len(pair) < 2:
            sys.stderr.write(f"ERROR -- Invalid value found: {pair}\n")
            exit(66)
        key, value = pair.split(':', 1)
        if key in unique_keys:
            sys.stderr.write(f"ERROR -- Duplicate key found: {key}\n")
            exit(66)
        unique_keys.add(key)
        comma_separated_content[key] = value
    return comma_separated_content

def split_by_comma_but_keep_maps(text):
    # Splits text by commas, but correctly handles nested maps by ignoring commas within maps.
    key_value_pairs = []
    current = ''
    stack = []
    for char in text:
        current += char
        if char == ',' and not stack:
            # Ensure there's no trailing comma
            if not current.strip() or current.strip() == ',':
                sys.stderr.write(f"ERROR -- Trailing or improperly formatted comma found in input: {text}\n")
                exit(66)
            key_value_pairs.append(current.strip().replace(',', ''))
            current = ''
        if char == '<':
            stack.append(char)
        elif char == '>':
            if stack:
                stack.pop()
    if stack:
        sys.stderr.write(f"ERROR -- Unmatched opening angle bracket found in input: {text}\n")
        exit(66)
    if current.strip():
        key_value_pairs.append(current.strip())
    return key_value_pairs

def is_empty_map(key, value):
    # Checks if a map is empty (both key and value are empty).
    return key == "" and value == ""

def main():
    # Main function to handle file input and output the parsed result.
    error = sys.stderr
    output = sys.stdout
    if len(sys.argv) != 2:
       sys.stderr.write("ERROR -- Invalid number of arguments\n")
       exit(66)
    file_to_read = sys.argv[1]
    try:
        file = open(file_to_read, "r")
        file_contents = file.read()
    except Exception as e:
        sys.stderr.write(f"ERROR -- Invalid file. Please re-check the file and try again.\n")
        exit(66)
   
    output.write(parse_file(file_contents.strip()))

if __name__ == "__main__":
    main()
