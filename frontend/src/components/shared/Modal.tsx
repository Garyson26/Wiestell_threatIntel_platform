'use client';

import { useEffect, useRef } from 'react';
import { X } from 'lucide-react';
import { cn } from '@/lib/utils';

interface ModalProps {
  isOpen: boolean;
  onClose: () => void;
  title: string;
  children: React.ReactNode;
  className?: string;
}

export default function Modal({ isOpen, onClose, title, children, className }: ModalProps) {
  const overlayRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const handleEsc = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    if (isOpen) {
      document.addEventListener('keydown', handleEsc);
      document.body.style.overflow = 'hidden';
    }
    return () => {
      document.removeEventListener('keydown', handleEsc);
      document.body.style.overflow = '';
    };
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  return (
    <div
      ref={overlayRef}
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm"
      onClick={(e) => e.target === overlayRef.current && onClose()}
    >
      <div className={cn('sentinel-card w-full max-w-lg mx-4 max-h-[80vh] flex flex-col animate-slide-up', className)}>
        <div className="flex items-center justify-between px-5 py-4 border-b border-sentinel-border">
          <h2 className="text-sm font-display font-semibold text-sentinel-text-primary">{title}</h2>
          <button
            onClick={onClose}
            className="p-1 rounded text-sentinel-text-muted hover:text-sentinel-text-primary hover:bg-sentinel-bg-hover transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>
        <div className="flex-1 overflow-auto p-5">
          {children}
        </div>
      </div>
    </div>
  );
}
