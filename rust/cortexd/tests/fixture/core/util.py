def fmt(value):
    return f"[{value}]"


class Registry:
    def lookup(self, key):
        return fmt(key)
