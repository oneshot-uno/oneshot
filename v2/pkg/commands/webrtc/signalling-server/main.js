"use strict";(()=>{var g=16384;var e=1*g;var n=8*g;var m="boundary";async function r(e,n,t){console.log("writeHeader: ",n,t);const o=(t==null?void 0:t.method)||"GET";let r=`${o} ${n} HTTP/1.1
`;let s=(t==null?void 0:t.headers)?t.headers:new Headers;if(s instanceof Headers){if(!s.has("User-Agent")){s.append("User-Agent",navigator.userAgent)}s.forEach((e,n)=>{r+=`${n}: ${e}
`})}else if(typeof s==="object"){if(s instanceof Array){var a=false;for(var i=0;i<s.length;i++){r+=`${s[i][0]}: ${s[i][1]}
`;if(s[i][0]==="User-Agent"){a=true}}if(!a){r+=`User-Agent: ${navigator.userAgent}
`}}else{if(!s["User-Agent"]){s["User-Agent"]=navigator.userAgent}for(const u in s){r+=`${u}: ${s[u]}
`}}}r+="\n";var c=void 0;var l=void 0;var d=new Promise((e,n)=>{c=e;l=n});const f=h(e,c,r);f();return d}function h(n,t,o){var r=g;const s=function(){while(o.length){if(n.bufferedAmount>n.bufferedAmountLowThreshold){n.onbufferedamountlow=()=>{n.onbufferedamountlow=null;s()}}if(o.length<r){r=o.length}const e=o.slice(0,r);o=o.slice(r);n.send(e);if(r!=g){t();return}}};return s}async function s(e,n){if(!n){e.send(new Uint8Array(0));e.send("");return Promise.resolve()}var t=void 0;var o=void 0;var r=void 0;var s=new Promise((e,n)=>{o=e;r=n});if(n instanceof ReadableStream){const i=await n.getReader().read();n=i.value}else{if(n instanceof FormData){l(e,n).then(()=>{o()});return s}else if(n instanceof Blob){t=await n.arrayBuffer()}else if(n instanceof URLSearchParams){t=(new TextEncoder).encode(n.toString())}else if(typeof n==="string"){t=(new TextEncoder).encode(n)}else if(n instanceof ArrayBuffer){t=n}}const a=c(e,t,o);a();return s}function c(n,t,o){var r=g;const s=function(){while(t.byteLength){if(n.bufferedAmount>n.bufferedAmountLowThreshold){n.onbufferedamountlow=()=>{n.onbufferedamountlow=null;s()}}if(t.byteLength<r){r=t.byteLength}const e=t.slice(0,r);t=t.slice(r);n.send(e);if(r!=g){n.send("");if(o)o();return}}};return s}async function l(u,h){const p=new TextEncoder;return new Promise(async(e,n)=>{for(const a of h.entries()){var t=`--${m}
`;const i=a[0];const c=a[1];if(typeof c==="string"){t+=`Content-Disposition: form-data; name="${i}"

`;u.send(p.encode(t));u.send(p.encode(c))}else{const l=c;t+=`Content-Disposition: form-data; name="${i}"; filename="${l.name}"
`;if(l.type){t+=`Content-Type: ${l.type}

`}else{t+="Content-Type: application/octet-stream\n\n"}u.send(p.encode(t));var o;var r=new Promise((e,n)=>{o=e});const d=new FileReader;var s=0;d.onerror=e=>{console.log("Error reading file",e)};d.onabort=e=>{console.log("File reading aborted",e)};d.onload=e=>{const n=e.target.result;u.send(n);s+=n.byteLength;if(s<l.size){f(s)}else{o()}};const f=e=>{d.readAsArrayBuffer(l.slice(e,e+g))};f(s);await r}}u.send(p.encode(`
--${m}--
`));u.send("");e()})}function w(e){const n=e.split("\n");const t={};for(const o of n){const r=o.search(":");if(r===-1){continue}const s=o.slice(0,r);const a=o.slice(r+1);t[s]=a.trim()}return t}function v(e){if(!e.startsWith("HTTP/1.1")){throw new Error(`unexpected status line: ${e}`)}const n=e.split(" ");if(n.length<3){throw new Error(`unexpected status line: ${e}`)}const t=parseInt(n[1]);const o=n.slice(2).join(" ");return{status:t,statusText:o}}function o(g){g.bufferedAmountLowThreshold=e;g.binaryType="arraybuffer";return(e,n)=>{var c=()=>{};var t=()=>{};const o=new Promise((e,n)=>{c=e;t=n});var l="";var d=-1;var f="";var u={};const h=new MessageChannel;var p=[];g.onmessage=o=>{if(o.data instanceof ArrayBuffer){if(d===-1){const r=l.slice(0,l.search("\n"));l=l.slice(l.search("\n")+1);const s=v(r);d=s.status;f=s.statusText;u=w(l);l="";p.push(o.data);h.port1.postMessage(null);const a=new Headers;for(const i in u){a.append(i,u[i])}let e={status:d,statusText:f,headers:a};let n=new ReadableStream({type:"bytes",start(e){if(e instanceof ReadableByteStreamController){if(e.byobRequest){throw new Error("byobRequest not supported")}}},pull(o){return new Promise((t,e)=>{h.port2.onmessage=e=>{const n=p.shift();if(!n){g.send("");o.close();t();return}o.enqueue(new Uint8Array(n));t()}})}});let t=new Response(n,e);c(t)}else{const e=o.data;if(0<e.byteLength){p.push(e);h.port1.postMessage(null)}}}else if(typeof o.data==="string"){if(d===-1){l+=o.data}else{h.port1.postMessage(null)}}};if((n==null?void 0:n.body)instanceof FormData){if(!n.headers){n.headers=new Headers}if(n.headers instanceof Headers){n.headers.append("Content-Type","multipart/form-data; boundary="+m)}else if(typeof n.headers==="object"){if(n.headers instanceof Array){n.headers.push(["Content-Type","multipart/form-data; boundary="+m])}else{n.headers["Content-Type"]="multipart/form-data; boundary="+m}}}r(g,e,n).then(()=>{s(g,n==null?void 0:n.body).catch(e=>{t(e)})}).catch(e=>{t(e)});return o}}var t=class{constructor(e,n){this.answered=false;this.connectionPromiseResolve=()=>{};this.onAnswer=n;this.peerConnection=new RTCPeerConnection({iceServers:[{urls:e}]});this.connectionPromise=new Promise((e,n)=>{this.connectionPromiseResolve=e});this._configurePeerConnection()}_configurePeerConnection(){const t=this.peerConnection;t.onicegatheringstatechange=e=>{console.log("onicegatheringstatechange",t.iceGatheringState);let n=e.target;if(n.iceGatheringState==="complete"&&n.localDescription){this.onAnswer(n.localDescription)}};t.ondatachannel=e=>{console.log("ondatachannel",e);window.fetch=o(e.channel);window.rtcReady=true;this.connectionPromiseResolve()};t.onnegotiationneeded=e=>{console.log("onnegotiationneeded")};t.onsignalingstatechange=e=>{console.log("onsignalingstatechange",t.signalingState)};t.oniceconnectionstatechange=e=>{console.log("oniceconnectionstatechange",t.iceConnectionState)}}async answerOffer(e){if(this.answered){return this.connectionPromise}const n=this.peerConnection;try{await n.setRemoteDescription(e);const t=await n.createAnswer();await n.setLocalDescription(t);this.answered=true}catch(e){console.error(e)}return this.connectionPromise}};function f(e){var n;if(e instanceof HTMLScriptElement){(n=e.parentNode)==null?void 0:n.replaceChild(a(e),e)}else{var t=-1,o=e.childNodes;while(++t<o.length){f(o[t])}}}function a(e){var n=document.createElement("script");n.text=e.innerHTML;var t=-1,o=e.attributes,r;while(++t<o.length){n.setAttribute((r=o[t]).name,r.value)}return n}function u(e,n){const t=document.createElement("a");t.setAttribute("style","display: none");document.body.appendChild(t);const o=new Blob([e],{type:"stream/octet"});const r=window.URL.createObjectURL(o);t.href=r;t.download=n;t.click();window.URL.revokeObjectURL(r)}var p=/^text\/.*$/;async function i(e,n){var t=await fetch(e,n);const o=t.headers;var r=o.get("Content-Type")?o.get("Content-Type"):"";r=r.split(";")[0];var s=o.get("Content-Disposition")?o.get("Content-Disposition"):"";if(!r){r="text/plain"}const a=y(s);if(a){const i=await t.blob();u(i,a);return}if(r.match(p)){const c=await t.text();if(r==="text/html"){const l=new DOMParser;const d=l.parseFromString(c,"text/html");document.body=d.body;f(document.body)}else{document.body.innerText=c;document.body.innerHTML=`<pre>${c}</pre>`}}else if(r.startsWith("application/")){const c=await t.blob();let e=new Blob([c],{type:r});let n=URL.createObjectURL(e);window.open(n,"_self")}else{console.log(`falling back to displaying body as preformatted text`);const c=await t.text();document.body.innerText=c;document.body.innerHTML=`<pre>${c}</pre>`}}function y(e){if(!e||!e.includes("attachment")){return""}const n=/filename[^;=\n]*=((['"]).*?\2|[^;\n]*)/;const t=n.exec(e);if(t!=null&&t[1]){return t[1].replace(/['"]/g,"")}return""}function d(n){return e=>{fetch("/api/sdp/answer",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({SessionID:n,Answer:e.sdp})}).then(e=>{if(e.status!==200){alert("failed to send answer: "+e.status+" "+e.statusText)}}).catch(e=>{alert(`failed to send answer: ${e}`)})}}function b(e){const n=JSON.stringify(e);const t=document.getElementById("answer-container");if(t){t.innerText=n}navigator.clipboard.writeText(n)}function T(e){const n=e.offer?JSON.parse(e.offer):void 0;if(!n||!e.iceURL){alert("missing offer or ice-url");return}new t(e.iceURL,e.onAnswer).answerOffer(n).then(()=>{i("/",{})})}var A=document.getElementById("connect-button");window.WebRTCClient=t;function C(){if(A){A.onclick=()=>{T(R(false))}}else{const e=document.createElement("span");e.innerText="tunnelling to oneshot server...";document.body.appendChild(e);T(R(true))}}function R(e){var n,t,o;const r={};var s=document.getElementById("ice-server-url");r.iceURL=s.value;(n=s.parentNode)==null?void 0:n.removeChild(s);var s=document.getElementById("session-id");r.sessionID=parseInt(s.value);(t=s.parentNode)==null?void 0:t.removeChild(s);var s=document.getElementById("offer-sdp");r.offer=s.value;(o=s.parentNode)==null?void 0:o.removeChild(s);if(e){r.onAnswer=d(r.sessionID)}else{r.onAnswer=b}return r}C()})();