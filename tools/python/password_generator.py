#!/usr/bin/env python3
"""
Password Generator - Cryptographically secure password generation
Part of Lackadaisical Anonymity Toolkit
"""

import secrets
import string
import argparse
import sys
from typing import List

class PasswordGenerator:
    """Generate cryptographically secure passwords"""
    
    def __init__(self):
        self.lowercase = string.ascii_lowercase
        self.uppercase = string.ascii_uppercase
        self.digits = string.digits
        self.symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        self.ambiguous = "il1Lo0O"
    
    def generate_password(self, length: int = 16, 
                         use_uppercase: bool = True,
                         use_digits: bool = True,
                         use_symbols: bool = True,
                         exclude_ambiguous: bool = False) -> str:
        """
        Generate a cryptographically secure random password
        
        Args:
            length: Password length (default: 16)
            use_uppercase: Include uppercase letters
            use_digits: Include digits
            use_symbols: Include symbols
            exclude_ambiguous: Exclude ambiguous characters (i, l, 1, L, o, 0, O)
        
        Returns:
            Generated password string
        """
        # Build character set
        chars = self.lowercase
        
        if use_uppercase:
            chars += self.uppercase
        if use_digits:
            chars += self.digits
        if use_symbols:
            chars += self.symbols
        
        # Remove ambiguous characters if requested
        if exclude_ambiguous:
            chars = ''.join(c for c in chars if c not in self.ambiguous)
        
        # Ensure we have at least one of each required type
        password = []
        
        # Add one of each required type first
        password.append(secrets.choice(self.lowercase))
        if use_uppercase:
            password.append(secrets.choice(self.uppercase))
        if use_digits:
            password.append(secrets.choice(self.digits))
        if use_symbols:
            password.append(secrets.choice(self.symbols))
        
        # Fill the rest randomly
        remaining = length - len(password)
        for _ in range(remaining):
            password.append(secrets.choice(chars))
        
        # Shuffle to avoid predictable patterns
        secrets.SystemRandom().shuffle(password)
        
        return ''.join(password)
    
    def generate_passphrase(self, word_count: int = 6,
                           separator: str = '-',
                           capitalize: bool = True,
                           include_number: bool = True) -> str:
        """
        Generate a memorable passphrase using word list
        
        Args:
            word_count: Number of words (default: 6)
            separator: Word separator (default: -)
            capitalize: Capitalize each word
            include_number: Add random number at end
        
        Returns:
            Generated passphrase
        """
        # EFF's short wordlist (subset for demo - in production use full 1296 word list)
        wordlist = [
            'able', 'acid', 'aged', 'also', 'area', 'army', 'away', 'baby',
            'back', 'ball', 'band', 'bank', 'base', 'bath', 'bear', 'beat',
            'been', 'beer', 'bell', 'belt', 'best', 'bill', 'bird', 'blow',
            'blue', 'boat', 'body', 'bomb', 'bond', 'bone', 'book', 'boom',
            'born', 'boss', 'both', 'bowl', 'bulk', 'burn', 'bush', 'busy',
            'cafe', 'cake', 'call', 'calm', 'came', 'camp', 'card', 'care',
            'case', 'cash', 'cast', 'cell', 'chat', 'chef', 'chip', 'city',
            'club', 'coal', 'coat', 'code', 'cold', 'come', 'cook', 'cool',
            'cope', 'copy', 'core', 'cost', 'crew', 'crop', 'dark', 'data',
            'date', 'dawn', 'days', 'dead', 'deal', 'dean', 'dear', 'debt',
            'deep', 'deer', 'demo', 'deny', 'desk', 'dial', 'diet', 'disc',
            'disk', 'dock', 'does', 'door', 'dose', 'down', 'draw', 'drew',
            'drop', 'drug', 'dual', 'duck', 'duke', 'dull', 'dust', 'duty',
            'each', 'earn', 'ease', 'east', 'easy', 'edge', 'else', 'even',
            'ever', 'evil', 'exit', 'face', 'fact', 'fail', 'fair', 'fall',
            'farm', 'fast', 'fate', 'fear', 'feed', 'feel', 'feet', 'fell',
            'felt', 'file', 'fill', 'film', 'find', 'fine', 'fire', 'firm',
            'fish', 'five', 'flag', 'flat', 'fled', 'flew', 'flow', 'folk',
            'food', 'foot', 'ford', 'form', 'fort', 'four', 'free', 'from',
            'fuel', 'full', 'fund', 'gain', 'game', 'gate', 'gave', 'gear',
            'gene', 'gift', 'girl', 'give', 'glad', 'goal', 'goes', 'gold',
            'golf', 'gone', 'good', 'gray', 'grew', 'grey', 'grow', 'gulf',
            'hair', 'half', 'hall', 'hand', 'hang', 'hard', 'harm', 'hate',
            'have', 'head', 'hear', 'heat', 'held', 'hell', 'help', 'here',
            'hero', 'high', 'hill', 'hire', 'hold', 'hole', 'holy', 'home',
            'hope', 'host', 'hour', 'huge', 'hung', 'hunt', 'hurt', 'idea',
            'inch', 'into', 'iron', 'item', 'jack', 'jane', 'jean', 'john',
            'join', 'jump', 'jury', 'just', 'keen', 'keep', 'kent', 'kept',
            'kick', 'kill', 'kind', 'king', 'knee', 'knew', 'know', 'lack',
            'lady', 'laid', 'lake', 'land', 'lane', 'last', 'late', 'lead',
            'left', 'less', 'life', 'lift', 'like', 'line', 'link', 'list',
            'live', 'load', 'loan', 'lock', 'long', 'look', 'lord', 'lose',
            'loss', 'lost', 'love', 'luck', 'made', 'mail', 'main', 'make',
            'male', 'mall', 'many', 'mark', 'mass', 'matt', 'meal', 'mean',
            'meat', 'meet', 'menu', 'mere', 'mike', 'mile', 'milk', 'mill',
            'mind', 'mine', 'miss', 'mode', 'mood', 'moon', 'more', 'most',
            'move', 'much', 'must', 'name', 'navy', 'near', 'neck', 'need',
            'news', 'next', 'nice', 'nick', 'nine', 'none', 'nose', 'note',
            'once', 'only', 'onto', 'open', 'oral', 'over', 'pace', 'pack',
            'page', 'paid', 'pain', 'pair', 'palm', 'park', 'part', 'pass',
            'past', 'path', 'paul', 'peak', 'pick', 'pill', 'pine', 'pink',
            'plan', 'play', 'plot', 'plug', 'plus', 'poet', 'poll', 'pond',
            'pool', 'poor', 'port', 'post', 'pull', 'pure', 'push', 'race',
            'rail', 'rain', 'rank', 'rare', 'rate', 'read', 'real', 'rear',
            'rely', 'rent', 'rest', 'rice', 'rich', 'ride', 'ring', 'rise',
            'risk', 'road', 'rock', 'role', 'roll', 'rome', 'roof', 'room',
            'root', 'rope', 'rose', 'rule', 'rush', 'ruth', 'safe', 'said',
            'sake', 'sale', 'salt', 'same', 'sand', 'save', 'seat', 'seed',
            'seek', 'seem', 'seen', 'self', 'sell', 'send', 'sent', 'sept',
            'ship', 'shop', 'shot', 'show', 'shut', 'sick', 'side', 'sign',
            'site', 'size', 'skin', 'slip', 'slow', 'snow', 'soft', 'soil',
            'sold', 'sole', 'some', 'song', 'soon', 'sort', 'soul', 'spot',
            'star', 'stay', 'step', 'stop', 'such', 'suit', 'sure', 'take',
            'tale', 'talk', 'tall', 'tank', 'tape', 'task', 'team', 'tell',
            'tend', 'term', 'test', 'text', 'than', 'that', 'them', 'then',
            'they', 'thin', 'this', 'thus', 'till', 'time', 'tiny', 'told',
            'toll', 'tone', 'tony', 'took', 'tool', 'tour', 'town', 'tree',
            'trim', 'trip', 'true', 'tune', 'turn', 'twin', 'type', 'unit',
            'upon', 'used', 'user', 'vary', 'vast', 'very', 'vice', 'view',
            'vote', 'wage', 'wait', 'wake', 'walk', 'wall', 'want', 'ward',
            'warm', 'wash', 'wave', 'ways', 'weak', 'wear', 'week', 'well',
            'went', 'were', 'west', 'what', 'when', 'whom', 'wide', 'wife',
            'wild', 'will', 'wind', 'wine', 'wing', 'wire', 'wise', 'wish',
            'with', 'wood', 'word', 'wore', 'work', 'worn', 'yard', 'yeah',
            'year', 'york', 'your', 'zero', 'zone'
        ]
        
        # Select random words
        words = [secrets.choice(wordlist) for _ in range(word_count)]
        
        # Capitalize if requested
        if capitalize:
            words = [w.capitalize() for w in words]
        
        # Join with separator
        passphrase = separator.join(words)
        
        # Add number if requested
        if include_number:
            number = secrets.randbelow(10000)
            passphrase += f"{separator}{number}"
        
        return passphrase
    
    def calculate_entropy(self, password: str) -> float:
        """Calculate password entropy in bits"""
        charset_size = 0
        
        if any(c in self.lowercase for c in password):
            charset_size += len(self.lowercase)
        if any(c in self.uppercase for c in password):
            charset_size += len(self.uppercase)
        if any(c in self.digits for c in password):
            charset_size += len(self.digits)
        if any(c in self.symbols for c in password):
            charset_size += len(self.symbols)
        
        import math
        entropy = len(password) * math.log2(charset_size) if charset_size > 0 else 0
        return entropy
    
    def assess_strength(self, password: str) -> str:
        """Assess password strength"""
        entropy = self.calculate_entropy(password)
        
        if entropy < 28:
            return "VERY WEAK"
        elif entropy < 36:
            return "WEAK"
        elif entropy < 60:
            return "FAIR"
        elif entropy < 128:
            return "STRONG"
        else:
            return "VERY STRONG"

def main():
    parser = argparse.ArgumentParser(
        description='Password Generator - Cryptographically secure passwords'
    )
    
    parser.add_argument(
        '--length', '-l',
        type=int,
        default=16,
        help='Password length (default: 16)'
    )
    
    parser.add_argument(
        '--count', '-c',
        type=int,
        default=1,
        help='Number of passwords to generate (default: 1)'
    )
    
    parser.add_argument(
        '--no-uppercase',
        action='store_true',
        help='Exclude uppercase letters'
    )
    
    parser.add_argument(
        '--no-digits',
        action='store_true',
        help='Exclude digits'
    )
    
    parser.add_argument(
        '--no-symbols',
        action='store_true',
        help='Exclude symbols'
    )
    
    parser.add_argument(
        '--exclude-ambiguous',
        action='store_true',
        help='Exclude ambiguous characters (i, l, 1, L, o, 0, O)'
    )
    
    parser.add_argument(
        '--passphrase',
        action='store_true',
        help='Generate passphrase instead of password'
    )
    
    parser.add_argument(
        '--words',
        type=int,
        default=6,
        help='Number of words in passphrase (default: 6)'
    )
    
    parser.add_argument(
        '--separator',
        default='-',
        help='Word separator for passphrase (default: -)'
    )
    
    parser.add_argument(
        '--show-entropy',
        action='store_true',
        help='Show password entropy and strength'
    )
    
    args = parser.parse_args()
    
    generator = PasswordGenerator()
    
    for i in range(args.count):
        if args.passphrase:
            password = generator.generate_passphrase(
                word_count=args.words,
                separator=args.separator
            )
        else:
            password = generator.generate_password(
                length=args.length,
                use_uppercase=not args.no_uppercase,
                use_digits=not args.no_digits,
                use_symbols=not args.no_symbols,
                exclude_ambiguous=args.exclude_ambiguous
            )
        
        print(password)
        
        if args.show_entropy:
            entropy = generator.calculate_entropy(password)
            strength = generator.assess_strength(password)
            print(f"  Entropy: {entropy:.1f} bits")
            print(f"  Strength: {strength}")
            print()
    
    return 0

if __name__ == '__main__':
    sys.exit(main())
