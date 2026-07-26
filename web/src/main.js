import './app.css'
import App from './App.svelte'

// Apply the saved theme before mount so the first paint is already correct (no dark→light flash).
if (localStorage.getItem('vmpulse_theme') === 'light') {
  document.documentElement.classList.add('light')
}

const app = new App({
  target: document.getElementById('app')
})

export default app
