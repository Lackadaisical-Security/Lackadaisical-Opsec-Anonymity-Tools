#!/usr/bin/env python3
"""
Biometric Spoofer - Defeat biometric authentication systems
Part of Lackadaisical Anonymity Toolkit
"""

import os
import sys
import time
import random
import hashlib
import numpy as np
from PIL import Image, ImageDraw, ImageFilter, ImageEnhance
import cv2
from typing import Tuple, List, Optional
import base64
import io

class BiometricSpoofer:
    """Tools for defeating biometric authentication"""
    
    def __init__(self):
        self.fingerprint_db = self._load_fingerprint_patterns()
        self.face_models = self._load_face_models()
    
    def _load_fingerprint_patterns(self):
        """Load common fingerprint patterns"""
        return {
            'arch': self._generate_arch_pattern,
            'loop': self._generate_loop_pattern,
            'whorl': self._generate_whorl_pattern,
            'composite': self._generate_composite_pattern
        }
    
    def _load_face_models(self):
        """Load face detection models"""
        try:
            # Try to load Haar Cascade for face detection
            cascade_path = cv2.data.haarcascades + 'haarcascade_frontalface_default.xml'
            return cv2.CascadeClassifier(cascade_path)
        except:
            return None
    
    def generate_synthetic_fingerprint(self, pattern_type: str = 'random', 
                                     size: Tuple[int, int] = (300, 400)) -> Image.Image:
        """Generate synthetic fingerprint image"""
        if pattern_type == 'random':
            pattern_type = random.choice(list(self.fingerprint_db.keys()))
        
        # Create base image
        img = Image.new('L', size, 255)
        draw = ImageDraw.Draw(img)
        
        # Generate pattern
        if pattern_type in self.fingerprint_db:
            pattern_func = self.fingerprint_db[pattern_type]
            pattern_func(draw, size)
        
        # Add noise and imperfections
        img = self._add_fingerprint_noise(img)
        
        # Apply realistic filters
        img = img.filter(ImageFilter.GaussianBlur(radius=0.5))
        img = ImageEnhance.Contrast(img).enhance(1.5)
        
        return img
    
    def _generate_arch_pattern(self, draw: ImageDraw.Draw, size: Tuple[int, int]):
        """Generate arch fingerprint pattern"""
        width, height = size
        center_x = width // 2
        
        # Draw arch ridges
        for i in range(0, height, 4):
            y = i
            curve_height = 20 * np.sin(np.pi * i / height)
            
            points = []
            for x in range(0, width, 2):
                offset = curve_height * np.sin(np.pi * x / width)
                points.append((x, y + offset))
            
            if len(points) > 1:
                draw.line(points, fill=0, width=1)
    
    def _generate_loop_pattern(self, draw: ImageDraw.Draw, size: Tuple[int, int]):
        """Generate loop fingerprint pattern"""
        width, height = size
        center_x, center_y = width // 2, height // 2
        
        # Draw loop ridges
        for radius in range(10, min(width, height) // 2, 4):
            # Upper part of loop
            draw.arc([(center_x - radius, center_y - radius),
                     (center_x + radius, center_y + radius)],
                    180, 0, fill=0, width=1)
            
            # Lower straight lines
            draw.line([(center_x - radius, center_y),
                      (center_x - radius, height)], fill=0, width=1)
            draw.line([(center_x + radius, center_y),
                      (center_x + radius, height)], fill=0, width=1)
    
    def _generate_whorl_pattern(self, draw: ImageDraw.Draw, size: Tuple[int, int]):
        """Generate whorl fingerprint pattern"""
        width, height = size
        center_x, center_y = width // 2, height // 2
        
        # Draw spiral ridges
        for i in range(100):
            angle = i * 0.1
            radius = 2 + i * 1.5
            
            x = center_x + radius * np.cos(angle)
            y = center_y + radius * np.sin(angle)
            
            if 0 <= x < width and 0 <= y < height:
                draw.ellipse([(x-1, y-1), (x+1, y+1)], fill=0)
    
    def _generate_composite_pattern(self, draw: ImageDraw.Draw, size: Tuple[int, int]):
        """Generate composite fingerprint pattern"""
        # Combine multiple patterns
        width, height = size
        
        # Split into regions
        self._generate_loop_pattern(draw, (width // 2, height))
        
        # Add some whorl elements
        temp_draw = ImageDraw.Draw(Image.new('L', size, 255))
        self._generate_whorl_pattern(temp_draw, size)
    
    def _add_fingerprint_noise(self, img: Image.Image) -> Image.Image:
        """Add realistic noise to fingerprint"""
        # Convert to numpy array
        img_array = np.array(img)
        
        # Add pores
        for _ in range(random.randint(50, 150)):
            x = random.randint(0, img_array.shape[1] - 1)
            y = random.randint(0, img_array.shape[0] - 1)
            if img_array[y, x] < 128:  # Only on ridges
                cv2.circle(img_array, (x, y), 1, 255, -1)
        
        # Add scratches
        for _ in range(random.randint(2, 5)):
            start = (random.randint(0, img_array.shape[1]),
                    random.randint(0, img_array.shape[0]))
            end = (random.randint(0, img_array.shape[1]),
                  random.randint(0, img_array.shape[0]))
            cv2.line(img_array, start, end, 255, 1)
        
        # Add smudges
        kernel = np.ones((3, 3), np.uint8)
        if random.random() > 0.5:
            x = random.randint(0, img_array.shape[1] - 20)
            y = random.randint(0, img_array.shape[0] - 20)
            img_array[y:y+20, x:x+20] = cv2.morphologyEx(
                img_array[y:y+20, x:x+20], cv2.MORPH_CLOSE, kernel)
        
        return Image.fromarray(img_array)
    
    def generate_face_spoof(self, base_image_path: Optional[str] = None) -> Image.Image:
        """Generate face spoof image with anti-liveness features"""
        if base_image_path and os.path.exists(base_image_path):
            img = Image.open(base_image_path)
        else:
            # Generate synthetic face
            img = self._generate_synthetic_face()
        
        # Apply anti-liveness techniques
        img = self._apply_liveness_spoofing(img)
        
        return img
    
    def _generate_synthetic_face(self) -> Image.Image:
        """Generate synthetic face image"""
        # Create base face shape
        size = (400, 400)
        img = Image.new('RGB', size, (255, 220, 177))  # Skin tone
        draw = ImageDraw.Draw(img)
        
        # Face oval
        face_bbox = [50, 50, 350, 350]
        draw.ellipse(face_bbox, fill=(255, 220, 177), outline=(200, 170, 140))
        
        # Eyes
        eye_y = 150
        left_eye = [120, eye_y-20, 170, eye_y+20]
        right_eye = [230, eye_y-20, 280, eye_y+20]
        
        draw.ellipse(left_eye, fill=(255, 255, 255), outline=(100, 100, 100))
        draw.ellipse(right_eye, fill=(255, 255, 255), outline=(100, 100, 100))
        
        # Pupils
        draw.ellipse([135, eye_y-10, 155, eye_y+10], fill=(50, 50, 200))
        draw.ellipse([245, eye_y-10, 265, eye_y+10], fill=(50, 50, 200))
        
        # Nose
        nose_points = [(200, 180), (180, 220), (200, 230), (220, 220)]
        draw.polygon(nose_points, outline=(200, 170, 140))
        
        # Mouth
        draw.arc([150, 250, 250, 290], 0, 180, fill=(200, 100, 100), width=3)
        
        return img
    
    def _apply_liveness_spoofing(self, img: Image.Image) -> Image.Image:
        """Apply techniques to defeat liveness detection"""
        # Add micro-expressions
        img_array = np.array(img)
        
        # Simulate blood flow (subtle red channel variation)
        red_channel = img_array[:, :, 0].astype(float)
        variation = np.sin(np.linspace(0, 2*np.pi, red_channel.shape[0]))[:, np.newaxis]
        red_channel += variation * 2
        img_array[:, :, 0] = np.clip(red_channel, 0, 255).astype(np.uint8)
        
        # Add texture for depth
        texture = np.random.normal(0, 2, img_array.shape[:2])
        for c in range(3):
            img_array[:, :, c] = np.clip(img_array[:, :, c] + texture, 0, 255)
        
        # Simulate reflections
        highlight = Image.new('L', img.size, 0)
        draw = ImageDraw.Draw(highlight)
        
        # Add specular highlights
        for _ in range(random.randint(3, 8)):
            x = random.randint(50, img.width - 50)
            y = random.randint(50, img.height - 50)
            radius = random.randint(5, 15)
            draw.ellipse([x-radius, y-radius, x+radius, y+radius], fill=30)
        
        highlight = highlight.filter(ImageFilter.GaussianBlur(radius=10))
        
        # Composite
        img = Image.fromarray(img_array)
        img = Image.composite(img, Image.new('RGB', img.size, (255, 255, 255)), highlight)
        
        return img
    
    def generate_iris_pattern(self, size: Tuple[int, int] = (200, 200)) -> Image.Image:
        """Generate synthetic iris pattern"""
        img = Image.new('RGB', size, (255, 255, 255))
        draw = ImageDraw.Draw(img)
        
        center_x, center_y = size[0] // 2, size[1] // 2
        
        # Pupil
        pupil_radius = 30
        draw.ellipse([center_x - pupil_radius, center_y - pupil_radius,
                     center_x + pupil_radius, center_y + pupil_radius],
                    fill=(0, 0, 0))
        
        # Iris patterns
        iris_radius = 80
        
        # Radial fibers
        for angle in range(0, 360, 3):
            rad = np.radians(angle)
            x1 = center_x + pupil_radius * np.cos(rad)
            y1 = center_y + pupil_radius * np.sin(rad)
            x2 = center_x + iris_radius * np.cos(rad)
            y2 = center_y + iris_radius * np.sin(rad)
            
            color_var = random.randint(-30, 30)
            color = (100 + color_var, 150 + color_var, 200 + color_var)
            draw.line([(x1, y1), (x2, y2)], fill=color, width=1)
        
        # Circular patterns
        for radius in range(pupil_radius + 5, iris_radius, 5):
            color_var = random.randint(-20, 20)
            color = (120 + color_var, 160 + color_var, 210 + color_var)
            draw.ellipse([center_x - radius, center_y - radius,
                         center_x + radius, center_y + radius],
                        outline=color, width=1)
        
        # Add crypts and furrows
        for _ in range(random.randint(5, 15)):
            angle = random.uniform(0, 2 * np.pi)
            radius = random.uniform(pupil_radius + 10, iris_radius - 10)
            x = center_x + radius * np.cos(angle)
            y = center_y + radius * np.sin(angle)
            crypt_size = random.randint(3, 8)
            draw.ellipse([x - crypt_size, y - crypt_size,
                         x + crypt_size, y + crypt_size],
                        fill=(80, 120, 160))
        
        # Apply blur for realism
        img = img.filter(ImageFilter.GaussianBlur(radius=1))
        
        return img
    
    def create_3d_face_model(self, face_image: Image.Image) -> bytes:
        """Create 3D face model data for depth spoofing"""
        # Generate depth map
        width, height = face_image.size
        depth_map = np.zeros((height, width), dtype=np.float32)
        
        # Create face-shaped depth
        center_x, center_y = width // 2, height // 2
        
        for y in range(height):
            for x in range(width):
                # Calculate distance from center
                dx = (x - center_x) / (width / 2)
                dy = (y - center_y) / (height / 2)
                
                # Elliptical face shape
                if dx**2 + dy**2 < 1:
                    # Depth based on position
                    depth = np.sqrt(1 - dx**2 - dy**2)
                    
                    # Add features depth
                    # Nose bump
                    if abs(dx) < 0.1 and -0.2 < dy < 0.2:
                        depth += 0.1
                    
                    # Eye sockets
                    if 0.2 < abs(dx) < 0.4 and -0.3 < dy < -0.1:
                        depth -= 0.05
                    
                    depth_map[y, x] = depth * 255
        
        # Convert to image
        depth_img = Image.fromarray(depth_map.astype(np.uint8))
        
        # Encode as base64
        buffer = io.BytesIO()
        depth_img.save(buffer, format='PNG')
        return base64.b64encode(buffer.getvalue())
    
    def defeat_voice_recognition(self, target_voice_sample: Optional[str] = None):
        """Generate voice spoofing data"""
        # This would require audio processing libraries
        # Placeholder for voice cloning implementation
        
        techniques = {
            'replay_attack': 'Record and replay target voice',
            'synthesis': 'Use TTS with voice cloning',
            'modulation': 'Real-time voice modulation',
            'deepfake': 'AI-generated voice samples'
        }
        
        return techniques
    
    def behavioral_biometric_spoofing(self):
        """Spoof behavioral biometrics"""
        
        # Keystroke dynamics spoofing
        def generate_keystroke_pattern(text: str) -> List[Tuple[str, float, float]]:
            """Generate realistic keystroke timing pattern"""
            pattern = []
            base_speed = random.uniform(0.1, 0.2)  # Average typing speed
            
            for i, char in enumerate(text):
                # Dwell time (key press duration)
                dwell = base_speed + random.gauss(0, 0.02)
                
                # Flight time (time between keys)
                if i > 0:
                    # Common bigrams type faster
                    if text[i-1:i+1] in ['th', 'he', 'in', 'er', 'an']:
                        flight = base_speed * 0.8 + random.gauss(0, 0.01)
                    else:
                        flight = base_speed + random.gauss(0, 0.03)
                else:
                    flight = 0
                
                pattern.append((char, dwell, flight))
            
            return pattern
        
        # Mouse dynamics spoofing
        def generate_mouse_pattern(start: Tuple[int, int], 
                                 end: Tuple[int, int]) -> List[Tuple[int, int, float]]:
            """Generate realistic mouse movement pattern"""
            points = []
            
            # Bezier curve for natural movement
            t_values = np.linspace(0, 1, 50)
            
            # Control points for curve
            control1 = (start[0] + random.randint(-50, 50),
                       start[1] + random.randint(-50, 50))
            control2 = (end[0] + random.randint(-50, 50),
                       end[1] + random.randint(-50, 50))
            
            for t in t_values:
                # Cubic Bezier formula
                x = ((1-t)**3 * start[0] + 
                     3*(1-t)**2*t * control1[0] + 
                     3*(1-t)*t**2 * control2[0] + 
                     t**3 * end[0])
                y = ((1-t)**3 * start[1] + 
                     3*(1-t)**2*t * control1[1] + 
                     3*(1-t)*t**2 * control2[1] + 
                     t**3 * end[1])
                
                # Add micro-movements
                x += random.gauss(0, 2)
                y += random.gauss(0, 2)
                
                # Timestamp
                timestamp = t * random.uniform(0.5, 1.5)  # Total movement time
                
                points.append((int(x), int(y), timestamp))
            
            return points
        
        return {
            'keystroke': generate_keystroke_pattern,
            'mouse': generate_mouse_pattern
        }


def main():
    """CLI interface"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Biometric Spoofer')
    parser.add_argument('--fingerprint', action='store_true', 
                       help='Generate synthetic fingerprint')
    parser.add_argument('--face', action='store_true',
                       help='Generate face spoof image')
    parser.add_argument('--iris', action='store_true',
                       help='Generate iris pattern')
    parser.add_argument('--pattern', choices=['arch', 'loop', 'whorl', 'composite', 'random'],
                       default='random', help='Fingerprint pattern type')
    parser.add_argument('--output', '-o', help='Output file path')
    
    args = parser.parse_args()
    
    spoofer = BiometricSpoofer()
    
    if args.fingerprint:
        print("Generating synthetic fingerprint...")
        img = spoofer.generate_synthetic_fingerprint(args.pattern)
        
        output_path = args.output or f'fingerprint_{args.pattern}_{int(time.time())}.png'
        img.save(output_path)
        print(f"Fingerprint saved to: {output_path}")
    
    elif args.face:
        print("Generating face spoof image...")
        img = spoofer.generate_face_spoof()
        
        output_path = args.output or f'face_spoof_{int(time.time())}.png'
        img.save(output_path)
        print(f"Face spoof saved to: {output_path}")
    
    elif args.iris:
        print("Generating iris pattern...")
        img = spoofer.generate_iris_pattern()
        
        output_path = args.output or f'iris_pattern_{int(time.time())}.png'
        img.save(output_path)
        print(f"Iris pattern saved to: {output_path}")
    
    else:
        parser.print_help()

if __name__ == '__main__':
    main()
