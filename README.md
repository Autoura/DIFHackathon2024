# Hotel Restaurant Personalised Dining Offers Demo

This simple hack was created as part of the 2024 DIF Hackathon https://difhackathon2024.devpost.com/

This hack shows:

* A hotel with a DID (issued by TBD), a consumer with a DID (issued by Autoura.me)
* Hotel restaurant has a list of specials
* Hotel is able to access guest's food preferences (using a DID authenticated API endpoint)
* A message is created that is personalised based on the guest's actual requirements
* Finally, the message is sent to the guest via DIDComm

### Make it work

Create a .env file and include VUE_APP_OPENAI= with your OpenAI API key.

#### Project setup
```
npm install
```

#### Compiles and hot-reloads for development
```
npm run serve
```

This all works on localhost, no need to build and publish.

#### Compiles and minifies for production
```
npm run build
```
