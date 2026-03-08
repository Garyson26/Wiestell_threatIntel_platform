# Frontend Public Assets

## Current Status

The app is currently using **text-based logos**. When you're ready, you can add PNG images to replace them.

## To Add Your Custom Logo (Optional)

### 1. Main Logo
- **File:** `Wiestell-Logo.png`
- **Purpose:** Main logo displayed on login, signup, and sidebar
- **Recommended size:** 360x120px (width x height) or similar aspect ratio
- **Format:** PNG with transparent background

### 2. Favicon
- **File:** `favicon.png`
- **Purpose:** Browser tab icon
- **Recommended size:** 32x32px or 64x64px
- **Format:** PNG

### 3. Apple Touch Icon (Optional)
- **File:** `apple-touch-icon.png`
- **Purpose:** Icon when website is added to iOS home screen
- **Recommended size:** 180x180px
- **Format:** PNG

## How to Add PNG Images

1. Place your `Wiestell-Logo.png` in this folder
2. Place your `favicon.png` in this folder (32x32 or 64x64 pixels)
3. Update the code in these files to use `<Image>` component:
   - `src/app/(bare)/login/page.tsx`
   - `src/app/(bare)/signup/page.tsx`
   - `src/components/layout/Sidebar.tsx`
   - `src/app/layout.tsx` (for favicon)
4. Restart your Next.js development server

The images will be automatically served from the `/` path.
