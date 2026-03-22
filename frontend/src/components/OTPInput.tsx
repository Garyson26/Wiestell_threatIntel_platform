'use client';

import { useState, useRef, useEffect, KeyboardEvent, ClipboardEvent } from 'react';

interface OTPInputProps {
  length?: number;
  value: string;
  onChange: (value: string) => void;
  autoFocus?: boolean;
}

export default function OTPInput({ 
  length = 6, 
  value, 
  onChange, 
  autoFocus = true 
}: OTPInputProps) {
  // Store the actual digit values
  const [digits, setDigits] = useState<string[]>(Array(length).fill(''));
  // Store display values (visible digit or '*')
  const [displayValues, setDisplayValues] = useState<string[]>(Array(length).fill(''));
  // Track which digit is currently being shown
  const [visibleIndex, setVisibleIndex] = useState<number | null>(null);
  const inputRefs = useRef<(HTMLInputElement | null)[]>([]);
  const timeoutRef = useRef<NodeJS.Timeout | null>(null);

  // Initialize from parent value
  useEffect(() => {
    if (value && value.length <= length) {
      const newDigits = value.split('').concat(Array(length - value.length).fill(''));
      setDigits(newDigits);
      setDisplayValues(newDigits.map((d) => (d ? '*' : '')));
    }
  }, [value, length]);

  // Auto-focus first input on mount
  useEffect(() => {
    if (autoFocus && inputRefs.current[0]) {
      inputRefs.current[0].focus();
    }
  }, [autoFocus]);

  // Handle digit visibility timer
  useEffect(() => {
    if (visibleIndex !== null) {
      // Clear any existing timeout
      if (timeoutRef.current) {
        clearTimeout(timeoutRef.current);
      }

      // Set new timeout to mask the digit after 1 second
      timeoutRef.current = setTimeout(() => {
        setDisplayValues((prev) => {
          const newDisplay = [...prev];
          if (digits[visibleIndex]) {
            newDisplay[visibleIndex] = '*';
          }
          return newDisplay;
        });
        setVisibleIndex(null);
      }, 1000);
    }

    return () => {
      if (timeoutRef.current) {
        clearTimeout(timeoutRef.current);
      }
    };
  }, [visibleIndex, digits]);

  const handleChange = (index: number, inputValue: string) => {
    // Only accept digits
    const digit = inputValue.replace(/[^0-9]/g, '').slice(-1);

    if (digit) {
      const newDigits = [...digits];
      const newDisplay = [...displayValues];

      newDigits[index] = digit;
      newDisplay[index] = digit; // Show the digit initially

      setDigits(newDigits);
      setDisplayValues(newDisplay);
      setVisibleIndex(index); // Mark this digit as visible

      // Notify parent
      onChange(newDigits.join(''));

      // Auto-focus next input
      if (index < length - 1 && inputRefs.current[index + 1]) {
        inputRefs.current[index + 1]?.focus();
      }
    } else if (inputValue === '') {
      // Handle clear
      const newDigits = [...digits];
      const newDisplay = [...displayValues];

      newDigits[index] = '';
      newDisplay[index] = '';

      setDigits(newDigits);
      setDisplayValues(newDisplay);

      // Notify parent
      onChange(newDigits.join(''));
    }
  };

  const handleKeyDown = (index: number, e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Backspace') {
      e.preventDefault();

      if (digits[index]) {
        // Clear current digit
        const newDigits = [...digits];
        const newDisplay = [...displayValues];

        newDigits[index] = '';
        newDisplay[index] = '';

        setDigits(newDigits);
        setDisplayValues(newDisplay);
        onChange(newDigits.join(''));
      } else if (index > 0) {
        // Move to previous input and clear it
        const newDigits = [...digits];
        const newDisplay = [...displayValues];

        newDigits[index - 1] = '';
        newDisplay[index - 1] = '';

        setDigits(newDigits);
        setDisplayValues(newDisplay);
        onChange(newDigits.join(''));

        inputRefs.current[index - 1]?.focus();
      }
    } else if (e.key === 'ArrowLeft' && index > 0) {
      e.preventDefault();
      inputRefs.current[index - 1]?.focus();
    } else if (e.key === 'ArrowRight' && index < length - 1) {
      e.preventDefault();
      inputRefs.current[index + 1]?.focus();
    }
  };

  const handlePaste = (e: ClipboardEvent<HTMLInputElement>) => {
    e.preventDefault();
    const pastedData = e.clipboardData.getData('text/plain').replace(/[^0-9]/g, '').slice(0, length);

    if (pastedData) {
      const newDigits = pastedData.split('').concat(Array(length - pastedData.length).fill(''));
      const newDisplay = newDigits.map((d) => (d ? '*' : ''));

      setDigits(newDigits);
      setDisplayValues(newDisplay);
      onChange(pastedData);

      // Focus last filled input or next empty one
      const focusIndex = Math.min(pastedData.length, length - 1);
      inputRefs.current[focusIndex]?.focus();
    }
  };

  const handleFocus = (index: number) => {
    // Select the content when focused
    inputRefs.current[index]?.select();
  };

  return (
    <div className="flex gap-2 justify-center">
      {Array.from({ length }).map((_, index) => (
        <input
          key={index}
          ref={(el) => {
            inputRefs.current[index] = el;
          }}
          type="text"
          inputMode="numeric"
          maxLength={1}
          value={displayValues[index]}
          onChange={(e) => handleChange(index, e.target.value)}
          onKeyDown={(e) => handleKeyDown(index, e)}
          onPaste={handlePaste}
          onFocus={() => handleFocus(index)}
          className="w-12 h-14 text-center text-2xl font-mono rounded bg-sentinel-bg-primary border border-sentinel-border text-sentinel-text-primary outline-none focus:border-sentinel-accent focus:ring-2 focus:ring-sentinel-accent/20 transition-all"
          aria-label={`Digit ${index + 1}`}
        />
      ))}
    </div>
  );
}
