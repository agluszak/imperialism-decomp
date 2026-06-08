def generate_dummies(start, end):
    for i in range(start, end):
        print(f"  virtual void vmethod_{i:04x}();")

generate_dummies(2, 38)
