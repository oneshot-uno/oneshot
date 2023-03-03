import { HTTPHeader } from "./types";
import { formDataToString } from "./util";

function httpHeaderToString(header: HTTPHeader): string {
    let result = "";
    for (const key in header) {
        result += `${key}: ${header[key]}\n`;
    }
    return result;
}

export class WebRTCXMLHttpRequest {
    channel: RTCDataChannel;
    method = "";
    url: string | URL = "";
    headers: HTTPHeader = {};
    eventListeners: { [key: string]: [EventListenerOrEventListenerObject] } = {};
    responseText = "";

    constructor(channel: RTCDataChannel) {
        if (!channel) {
            throw new Error("channel is null");
        }
        this.channel = channel;
    }

    open(method: string, url: string | URL): void {
        this.method = method;
        this.url = url;
    }

    setRequestHeader(key: string, value: string): void {
        this.headers[key] = value;
    }

    send(body?: FormData | null | undefined) {
        if (body instanceof FormData) {
            formDataToString(body, "boundary").then((b) => {
                this.headers['Content-Type'] = `multipart/form-data; boundary=boundary`;
                this.headers['Content-Length'] = b.length.toString();
                const request = `${this.method} ${this.url} HTTP/1.1\n${httpHeaderToString(this.headers)}\n${b}`;
                const f = (event: MessageEvent) => {
                    // send the response to the event listeners for "load"
                    this.eventListeners['load'].forEach((listener: EventListenerOrEventListenerObject) => {
                        this.responseText = event.data;
                        (listener as EventListenerObject)?.handleEvent?.(event);
                        (listener as EventListener)?.call?.(this, event);
                    });
                };
                this.channel.onmessage = f.bind(this);
                this.channel.send(request);
            });
        } else {
            const request = `${this.method} ${this.url} HTTP/1.1\n${httpHeaderToString(this.headers)}\n`;
            const f = (event: MessageEvent) => {
                // send the response to the event listeners for "load"
                this.eventListeners['load'].forEach((listener: EventListenerOrEventListenerObject) => {
                    this.responseText = event.data;
                    (listener as EventListenerObject)?.handleEvent?.(event);
                    (listener as EventListener)?.call?.(this, event);
                });
            };
            this.channel.onmessage = f.bind(this);
            this.channel.send(request);
        }
    }

    addEventListener(event: string, listener: EventListenerOrEventListenerObject): void {
        let f = new FormData();
        let listeners = this.eventListeners[event];
        if (!listeners) {
            listeners = [listener];
        } else {
            listeners.push(listener);
        }
        this.eventListeners[event] = listeners;
    }
};