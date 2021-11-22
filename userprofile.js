var myHeaders = new Headers();
myHeaders.set('Cache-Control', 'no-store');
var urlParams = new URLSearchParams(window.location.search);
var tokens;
var domain = "indigo-lvts";
var region = "ap-northeast-1";
var appClientId = "1j8u6bh696ahk7o6to7345rqba";
var appClientSecret = "btje9qu2d5p0dpvt9afoipqso8k0mkhnm8u591qc6q4am3v6mcb";
var userPoolId = "ap-northeast-1_uEneS3iCd";
var redirectURI = window.location.origin;

//Convert Payload from Base64-URL to JSON
const decodePayload = payload => {
  const cleanedPayload = payload.replace(/-/g, '+').replace(/_/g, '/');
  const decodedPayload = atob(cleanedPayload)
  const uriEncodedPayload = Array.from(decodedPayload).reduce((acc, char) => {
    const uriEncodedChar = ('00' + char.charCodeAt(0).toString(16)).slice(-2)
    return `${acc}%${uriEncodedChar}`
  }, '')
  const jsonPayload = decodeURIComponent(uriEncodedPayload);

  return JSON.parse(jsonPayload)
}

//Parse JWT Payload
const parseJWTPayload = token => {
    const [header, payload, signature] = token.split('.');
    const jsonPayload = decodePayload(payload)

    return jsonPayload
};

//Parse JWT Header
const parseJWTHeader = token => {
    const [header, payload, signature] = token.split('.');
    const jsonHeader = decodePayload(header)

    return jsonHeader
};

//Generate a Random String
const getRandomString = () => {
    const randomItems = new Uint32Array(28);
    crypto.getRandomValues(randomItems);
    const binaryStringItems = randomItems.map(dec => `0${dec.toString(16).substr(-2)}`)
    return binaryStringItems.reduce((acc, item) => `${acc}${item}`, '');
}

//Encrypt a String with SHA256
const encryptStringWithSHA256 = async str => {
    const PROTOCOL = 'SHA-256'
    const textEncoder = new TextEncoder();
    const encodedData = textEncoder.encode(str);
    return crypto.subtle.digest(PROTOCOL, encodedData);
}

//Convert Hash to Base64-URL
const hashToBase64url = arrayBuffer => {
    const items = new Uint8Array(arrayBuffer)
    const stringifiedArrayHash = items.reduce((acc, i) => `${acc}${String.fromCharCode(i)}`, '')
    const decodedHash = btoa(stringifiedArrayHash)

    const base64URL = decodedHash.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    return base64URL
}

// Main Function
async function main() {
  var code = urlParams.get('code');

  //If code not present then request code else request tokens
  if (code == null){

    // Create random "state"
    var state = getRandomString();
    sessionStorage.setItem("pkce_state", state);

    // Create PKCE code verifier
    var code_verifier = getRandomString();
    sessionStorage.setItem("code_verifier", code_verifier);

    // Create code challenge
    var arrayHash = await encryptStringWithSHA256(code_verifier);
    var code_challenge = hashToBase64url(arrayHash);
    sessionStorage.setItem("code_challenge", code_challenge)

	console.log("https://"+domain+".auth."+region+".amazoncognito.com/oauth2/authorize?response_type=code&state="+state+"&client_id="+appClientId+"&redirect_uri="+redirectURI+"&scope=openid&code_challenge_method=S256&code_challenge="+code_challenge);
    // Redirtect user-agent to /authorize endpoint
    location.href = "https://"+domain+".auth."+region+".amazoncognito.com/oauth2/authorize?response_type=code&state="+state+"&client_id="+appClientId+"&redirect_uri="+redirectURI+"&code_challenge_method=S256&code_challenge="+code_challenge;
  } else {
 
    // Verify state matches
    state = urlParams.get('state');
    if(sessionStorage.getItem("pkce_state") != state) {
        alert("Invalid state");
    } else {

	// remove params from url
	window.history.replaceState({}, document.title, "/");

    // Fetch OAuth2 tokens from Cognito
    code_verifier = sessionStorage.getItem('code_verifier');
  await fetch("https://"+domain+".auth."+region+".amazoncognito.com/oauth2/token?grant_type=authorization_code&client_id="+appClientId+"&client_secret="+appClientSecret+"&code_verifier="+code_verifier+"&redirect_uri="+redirectURI+"&code="+ code,{
  method: 'post',
  headers: {
    'Content-Type': 'application/x-www-form-urlencoded'
  }})
  .then((response) => {
    return response.json();
  })
  .then((data) => {

    // Verify id_token
    tokens=data;
	console.log(tokens.access_token);
	localStorage.setItem("access_token", tokens.access_token);
    var idVerified = verifyToken (tokens.id_token);
	console.log('0000000000000000', idVerified);
    Promise.resolve(idVerified).then(function(value) {
      if (value.localeCompare("verified")){
        alert("Invalid ID Token - "+ value);
        return;
      }
      });
    // Display tokens
    //document.getElementById("id_token").innerHTML = JSON.stringify(parseJWTPayload(tokens.id_token),null,'\t');
    document.getElementById("id_token").innerHTML = JSON.stringify(tokens.id_token);
    //document.getElementById("access_token").innerHTML = JSON.stringify(parseJWTPayload(tokens.access_token),null,'\t');
    document.getElementById("access_token").innerHTML = JSON.stringify(tokens.access_token);
  });

    // Fetch from /user_info
    await fetch("https://"+domain+".auth."+region+".amazoncognito.com/oauth2/userInfo",{
      method: 'post',
      headers: {
        'authorization': 'Bearer ' + tokens.access_token
    }})
    .then((response) => {
      return response.json();
    })
    .then((data) => {
      // Display user information
      //document.getElementById("userInfo").innerHTML = JSON.stringify(data, null,'\t');
    });
	
	const role = parseJWTPayload(tokens.access_token);
	
	console.log(role['cognito:groups'][1]);
	
	//fetch permission from lambda function aws
	await fetch("https://uspb5isbwe.execute-api.ap-northeast-1.amazonaws.com/QA/userinfo", {
		method: 'post',
		headers: {
			"Content-Type": "Application/Json",
			"Authorization": tokens.access_token
		},
		body: JSON.stringify({"role": role['cognito:groups'][1]})
	})
	.then((resp) => {
		return resp.json();
	})
	.then((dataList) => {
		console.log(dataList);
		const res = dataList;
		let permission = [];
		if(res.body && res.body.length > 0) {
			permission = res.body[0].permissions
			if(permission.length > 0) {
				console.log(permission);
				var completelist= document.getElementById("menu");
				permission.forEach(function(item) {				   
				   completelist.innerHTML += "<li class='list-group-item active'>" + item.key + "</li>";				   
				});
			}
		}
	});
	
  }}}
  main();
  
  
  const callApi = async () => {
  try {
	  
    const token = localStorage.getItem("access_token");
	

    // Make the call to the API, setting the token
    // in the Authorization header
    const response = await fetch("http://localhost:3001/api/myfirstapi", {
      headers: {
        accesstoken: token
      }
    });

    // Fetch the JSON result
    const responseData = await response.json();

   console.log(responseData);

} catch (e) {
    // Display errors in the console
    console.error(e);
  }
};