<template>
  <div class="about">
    <h2>Login:</h2>
    <p>{{ Login() }}</p>
    <h2>Access Token</h2>
    <p>{{ AccessToken() }}</p>
    <h2>Refresh Token</h2>
    <p>{{ RefreshToken() }}</p>
    <p><button @click="LogOut">Log Out</button></p>
  </div>
</template>

<script lang="ts">
import { defineComponent } from "vue";
import KeyCloakService from "../security/KeycloakService";

KeyCloakService.CallLogin();

export default defineComponent({
  name: "LoginComponent",
  methods: {
    Login() {
      return KeyCloakService.GetUserName();
    },
    AccessToken() {
      return KeyCloakService.GetAccesToken();
    },
    LogOut() {
      return KeyCloakService.CallLogOut();
    },
    RefreshToken() {
      return KeyCloakService.GetRefreshToken();
    },
  },
});
</script>
