import React from 'react';

interface EmeshLogoProps {
  size?: number;
  className?: string;
}

export const EmeshLogo: React.FC<EmeshLogoProps> = ({ size = 36, className = '' }) => {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 48 48"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      aria-hidden="true"
      className={className}
    >
      <rect width="48" height="48" rx="12" className="fill-[#0A1433] dark:fill-[#112254]" />
      <path
        d="M24 9L37 15.5V25.2C37 32.8 31.4 38.4 24 40.5C16.6 38.4 11 32.8 11 25.2V15.5L24 9Z"
        stroke="white"
        strokeWidth="2.2"
        strokeLinejoin="round"
      />
      <circle cx="24" cy="21" r="3" fill="#60A5FA" />
      <circle cx="18" cy="28" r="2.2" fill="white" />
      <circle cx="30" cy="28" r="2.2" fill="white" />
      <path
        d="M24 21L18 28M24 21L30 28M18 28H30"
        stroke="white"
        strokeWidth="1.6"
        strokeLinecap="round"
      />
    </svg>
  );
};
