<script>
  import { token } from './lib/stores.js'
  import Login from './routes/Login.svelte'
  import Dashboard from './routes/Dashboard.svelte'
</script>

{#if $token}
  <Dashboard />
{:else}
  <Login />
{/if}
