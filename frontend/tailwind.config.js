/** @type {import('tailwindcss').Config} */
export default {
    content: [
        "./index.html",
        "./src/**/*.{js,jsx}",
    ],
    theme: {
        extend: {
            colors: {
                bg: {
                    primary: '#0d1117',
                    surface: '#161b22',
                    elevated: '#1c2128',
                },
                border: {
                    DEFAULT: '#21262d',
                    light: '#30363d',
                },
                accent: {
                    DEFAULT: '#58a6ff',
                    hover: '#79c0ff',
                },
                success: '#3fb950',
                warning: '#d29922',
                danger: '#f85149',
                text: {
                    primary: '#e6edf3',
                    muted: '#7d8590',
                },
            },
            fontFamily: {
                mono: ['JetBrains Mono', 'monospace'],
                sans: ['Inter', 'system-ui', 'sans-serif'],
            },
        },
    },
    plugins: [],
}
