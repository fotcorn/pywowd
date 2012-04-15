
class RC4():
    def set_key(self, k):
        L = len(k)
        self.s = range(0, 256)
        j = 0
        for i in range(0, 256):
            j = (j + self.s[i] + ord(k[i % L])) % 256
            self.s[i], self.s[j] = self.s[j], self.s[i]
        self.i = 0
        self.j = 0
    
    def update(self, data):
        encrypted = []
        for c in data:
            self.i = (self.i + 1) % 256
            self.j = (self.j + self.s[self.i]) % 256
            self.s[self.i], self.s[self.j] = self.s[self.j], self.s[self.i]
            r = self.s[(self.s[self.i] + self.s[self.j]) % 256]
            encrypted.append(chr(r ^ ord(c)))
        return ''.join(encrypted)