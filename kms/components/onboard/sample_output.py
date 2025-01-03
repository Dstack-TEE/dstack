#!/usr/bin/env python3
from cert_generator import generate_all_keys

def main():
    keys_json = generate_all_keys("dstack.ai", "DStack")
    print(keys_json)

if __name__ == "__main__":
    main()
