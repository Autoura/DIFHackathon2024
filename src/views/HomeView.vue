<template>
  <div class="home">

    <div style="padding-top:30px; padding-bottom:30px;">
      <img alt="Autoura Logo" height="150" src="https://www.autoura.com/img/autoura.png" style="padding-right: 20px;">
      <img alt="TBD Logo" height="150" src="../assets/tbd.png" style="padding-left: 20px;">
    </div>

    <h1>Improved dining offers using AI agents</h1>

    <div v-if="Object.keys(preferences).length === 0 && !my_did">
      <p>Hey, you don't have a hotel DID yet!</p>
      <button @click="createDid" v-if="!my_did">Create a DID</button>
    </div>

    <template v-else>

      <template v-if="!seen_assumptions">

        <h2>Starting assumptions</h2>
        <h3>The hotel has a long term DID (in this case issued by TBD)</h3>
        <h3>The consumer has a DID (in this case issued by Autoura.me)</h3>

        <div style="display: flex; justify-content: space-between; gap: 25px;">
          <div style="flex: 1;">
            <h3>Consumer DID (from Autoura.me)</h3>
            <p class="did"><strong>{{consumer_did}}</strong></p>
          </div>
          <div style="flex: 1;">
            <h3>Hotel DID (from TBD)</h3>
            <p class="did"><strong>{{my_did.uri}}</strong></p>
          </div>
        </div>

        <button @click="seen_assumptions = true">OK understood</button>

      </template>

      <template v-if="seen_assumptions && Object.keys(preferences).length === 0">

        <h2>Ok now we can begin!</h2>

        <h3>Your dining specials (edit if you wish)...</h3>

        <div style="padding:20px; text-align:left">
          <textarea id="specialsText" v-model="specials"
                    :rows="15"
                    style="width: 100%; padding: 12px; border: 1px solid #ccc; border-radius: 5px; font-size: 16px; line-height: 1.5; resize: vertical;"></textarea>
        </div>

        <button @click="get_preferences">What will the guest like?</button>

      </template>

      <template v-if="preferences && Object.keys(preferences).length > 0 && !message">

        <h3>Preferences (Autoura.me)</h3>
        <pre style="text-align:left; font-size: 16px; line-height: 1.5;"
             v-if="preferences">{{JSON.stringify(preferences.discovery.food, null, 2)}}
{{JSON.stringify(preferences.service.food, null, 2)}}
        </pre>

        <button @click="get_message" v-if="preferences && this.specials">Apply some AI magic ✨</button>

      </template>

      <template v-else-if="message && message_status === 'notsent'">

        <h3>Personalised message for the guest</h3>
        <pre style="text-align:left" v-if="message">{{message}}</pre>

        <button @click="send_message" v-if="message">Send it! (DIDComm)</button>

      </template>

      <template v-else-if="message_status ==='sent'">
        <p>Sent via DIDComm!</p>
      </template>


    </template>

  </div>
</template>

<script>

import {didTools} from '@/common/did';
import {hotel} from '@/common/hotel';
import {autoura} from '@/common/autoura';
import {openai} from '@/common/openai';

export default {
  name: 'HomeView',
  data() {
    return {
      my_did: null,
      consumer_did: didTools.get_test_did(),
      specials: hotel.get_specials(),
      preferences: {},
      message: '',
      message_status: 'notsent',
      seen_assumptions: false
    };
  },
  mounted() {
    console.log();
  },
  methods: {
    async createDid() {
      this.my_did = await didTools.create_my_did();
    },
    async get_preferences() {
      let preferences_response = await autoura.callAutouraService(this.my_did);
      this.preferences = preferences_response.response;
    },
    async get_message() {
      let prompt = openai.create_prompt(this.preferences, this.specials);
      this.message = await openai.ask_openai(prompt);
    },
    async send_message() {

      let response = await didTools.sendDIDComm(this.message, this.my_did);

      console.log(response);

      if (response.success) {
        this.message_status = 'sent';
      }

    }
  }
};
</script>

<style scoped>

p.did {
  max-width: 100%;
  word-break: break-all;
  white-space: normal;
}

button {
  padding: 10px 20px;
  font-size: 16px;
  cursor: pointer;
}
</style>