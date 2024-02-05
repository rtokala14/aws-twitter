var __defProp = Object.defineProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, {
      get: all[name],
      enumerable: true,
      configurable: true,
      set: (newValue) => all[name] = () => newValue
    });
};

// node_modules/hono/dist/utils/url.js
var splitPath = (path) => {
  const paths = path.split("/");
  if (paths[0] === "") {
    paths.shift();
  }
  return paths;
};
var splitRoutingPath = (routePath) => {
  const { groups, path } = extractGroupsFromPath(routePath);
  const paths = splitPath(path);
  return replaceGroupMarks(paths, groups);
};
var extractGroupsFromPath = (path) => {
  const groups = [];
  path = path.replace(/\{[^}]+\}/g, (match, index) => {
    const mark = `@${index}`;
    groups.push([mark, match]);
    return mark;
  });
  return { groups, path };
};
var replaceGroupMarks = (paths, groups) => {
  for (let i = groups.length - 1;i >= 0; i--) {
    const [mark] = groups[i];
    for (let j = paths.length - 1;j >= 0; j--) {
      if (paths[j].includes(mark)) {
        paths[j] = paths[j].replace(mark, groups[i][1]);
        break;
      }
    }
  }
  return paths;
};
var patternCache = {};
var getPattern = (label) => {
  if (label === "*") {
    return "*";
  }
  const match = label.match(/^\:([^\{\}]+)(?:\{(.+)\})?$/);
  if (match) {
    if (!patternCache[label]) {
      if (match[2]) {
        patternCache[label] = [label, match[1], new RegExp("^" + match[2] + "$")];
      } else {
        patternCache[label] = [label, match[1], true];
      }
    }
    return patternCache[label];
  }
  return null;
};
var getPath = (request) => {
  const match = request.url.match(/^https?:\/\/[^/]+(\/[^?]*)/);
  return match ? match[1] : "";
};
var getQueryStrings = (url) => {
  const queryIndex = url.indexOf("?", 8);
  return queryIndex === -1 ? "" : "?" + url.slice(queryIndex + 1);
};
var getPathNoStrict = (request) => {
  const result = getPath(request);
  return result.length > 1 && result[result.length - 1] === "/" ? result.slice(0, -1) : result;
};
var mergePath = (...paths) => {
  let p = "";
  let endsWithSlash = false;
  for (let path of paths) {
    if (p[p.length - 1] === "/") {
      p = p.slice(0, -1);
      endsWithSlash = true;
    }
    if (path[0] !== "/") {
      path = `/${path}`;
    }
    if (path === "/" && endsWithSlash) {
      p = `${p}/`;
    } else if (path !== "/") {
      p = `${p}${path}`;
    }
    if (path === "/" && p === "") {
      p = "/";
    }
  }
  return p;
};
var checkOptionalParameter = (path) => {
  if (!path.match(/\:.+\?$/))
    return null;
  const segments = path.split("/");
  const results = [];
  let basePath = "";
  segments.forEach((segment) => {
    if (segment !== "" && !/\:/.test(segment)) {
      basePath += "/" + segment;
    } else if (/\:/.test(segment)) {
      if (/\?/.test(segment)) {
        if (results.length === 0 && basePath === "") {
          results.push("/");
        } else {
          results.push(basePath);
        }
        const optionalSegment = segment.replace("?", "");
        basePath += "/" + optionalSegment;
        results.push(basePath);
      } else {
        basePath += "/" + segment;
      }
    }
  });
  return results.filter((v, i, a) => a.indexOf(v) === i);
};
var _decodeURI = (value) => {
  if (!/[%+]/.test(value)) {
    return value;
  }
  if (value.indexOf("+") !== -1) {
    value = value.replace(/\+/g, " ");
  }
  return /%/.test(value) ? decodeURIComponent_(value) : value;
};
var _getQueryParam = (url, key, multiple) => {
  let encoded;
  if (!multiple && key && !/[%+]/.test(key)) {
    let keyIndex2 = url.indexOf(`?${key}`, 8);
    if (keyIndex2 === -1) {
      keyIndex2 = url.indexOf(`&${key}`, 8);
    }
    while (keyIndex2 !== -1) {
      const trailingKeyCode = url.charCodeAt(keyIndex2 + key.length + 1);
      if (trailingKeyCode === 61) {
        const valueIndex = keyIndex2 + key.length + 2;
        const endIndex = url.indexOf("&", valueIndex);
        return _decodeURI(url.slice(valueIndex, endIndex === -1 ? undefined : endIndex));
      } else if (trailingKeyCode == 38 || isNaN(trailingKeyCode)) {
        return "";
      }
      keyIndex2 = url.indexOf(`&${key}`, keyIndex2 + 1);
    }
    encoded = /[%+]/.test(url);
    if (!encoded) {
      return;
    }
  }
  const results = {};
  encoded ?? (encoded = /[%+]/.test(url));
  let keyIndex = url.indexOf("?", 8);
  while (keyIndex !== -1) {
    const nextKeyIndex = url.indexOf("&", keyIndex + 1);
    let valueIndex = url.indexOf("=", keyIndex);
    if (valueIndex > nextKeyIndex && nextKeyIndex !== -1) {
      valueIndex = -1;
    }
    let name = url.slice(keyIndex + 1, valueIndex === -1 ? nextKeyIndex === -1 ? undefined : nextKeyIndex : valueIndex);
    if (encoded) {
      name = _decodeURI(name);
    }
    keyIndex = nextKeyIndex;
    if (name === "") {
      continue;
    }
    let value;
    if (valueIndex === -1) {
      value = "";
    } else {
      value = url.slice(valueIndex + 1, nextKeyIndex === -1 ? undefined : nextKeyIndex);
      if (encoded) {
        value = _decodeURI(value);
      }
    }
    if (multiple) {
      if (!(results[name] && Array.isArray(results[name]))) {
        results[name] = [];
      }
      results[name].push(value);
    } else {
      results[name] ?? (results[name] = value);
    }
  }
  return key ? results[key] : results;
};
var getQueryParam = _getQueryParam;
var getQueryParams = (url, key) => {
  return _getQueryParam(url, key, true);
};
var decodeURIComponent_ = decodeURIComponent;

// node_modules/hono/dist/utils/cookie.js
var validCookieNameRegEx = /^[\w!#$%&'*.^`|~+-]+$/;
var validCookieValueRegEx = /^[ !#-:<-[\]-~]*$/;
var parse = (cookie, name) => {
  const pairs = cookie.trim().split(";");
  return pairs.reduce((parsedCookie, pairStr) => {
    pairStr = pairStr.trim();
    const valueStartPos = pairStr.indexOf("=");
    if (valueStartPos === -1)
      return parsedCookie;
    const cookieName = pairStr.substring(0, valueStartPos).trim();
    if (name && name !== cookieName || !validCookieNameRegEx.test(cookieName))
      return parsedCookie;
    let cookieValue = pairStr.substring(valueStartPos + 1).trim();
    if (cookieValue.startsWith('"') && cookieValue.endsWith('"'))
      cookieValue = cookieValue.slice(1, -1);
    if (validCookieValueRegEx.test(cookieValue))
      parsedCookie[cookieName] = decodeURIComponent_(cookieValue);
    return parsedCookie;
  }, {});
};
var _serialize = (name, value, opt = {}) => {
  let cookie = `${name}=${value}`;
  if (opt && typeof opt.maxAge === "number" && opt.maxAge >= 0) {
    cookie += `; Max-Age=${Math.floor(opt.maxAge)}`;
  }
  if (opt.domain) {
    cookie += `; Domain=${opt.domain}`;
  }
  if (opt.path) {
    cookie += `; Path=${opt.path}`;
  }
  if (opt.expires) {
    cookie += `; Expires=${opt.expires.toUTCString()}`;
  }
  if (opt.httpOnly) {
    cookie += "; HttpOnly";
  }
  if (opt.secure) {
    cookie += "; Secure";
  }
  if (opt.sameSite) {
    cookie += `; SameSite=${opt.sameSite}`;
  }
  if (opt.partitioned) {
    cookie += "; Partitioned";
  }
  return cookie;
};
var serialize = (name, value, opt = {}) => {
  value = encodeURIComponent(value);
  return _serialize(name, value, opt);
};

// node_modules/hono/dist/helper/html/index.js
var raw = (value, callbacks) => {
  const escapedString = new String(value);
  escapedString.isEscaped = true;
  escapedString.callbacks = callbacks;
  return escapedString;
};

// node_modules/hono/dist/utils/html.js
var HtmlEscapedCallbackPhase = {
  Stringify: 1,
  BeforeStream: 2,
  Stream: 3
};
var resolveCallback = async (str, phase, preserveCallbacks, context, buffer) => {
  const callbacks = str.callbacks;
  if (!callbacks?.length) {
    return Promise.resolve(str);
  }
  if (buffer) {
    buffer[0] += str;
  } else {
    buffer = [str];
  }
  const resStr = Promise.all(callbacks.map((c) => c({ phase, buffer, context }))).then((res) => Promise.all(res.filter(Boolean).map((str2) => resolveCallback(str2, phase, false, context, buffer))).then(() => buffer[0]));
  if (preserveCallbacks) {
    return raw(await resStr, callbacks);
  } else {
    return resStr;
  }
};

// node_modules/hono/dist/utils/stream.js
var StreamingApi = class {
  constructor(writable, _readable) {
    this.abortSubscribers = [];
    this.writable = writable;
    this.writer = writable.getWriter();
    this.encoder = new TextEncoder;
    const reader = _readable.getReader();
    this.responseReadable = new ReadableStream({
      async pull(controller) {
        const { done, value } = await reader.read();
        done ? controller.close() : controller.enqueue(value);
      },
      cancel: () => {
        this.abortSubscribers.forEach((subscriber) => subscriber());
      }
    });
  }
  async write(input) {
    try {
      if (typeof input === "string") {
        input = this.encoder.encode(input);
      }
      await this.writer.write(input);
    } catch (e) {
    }
    return this;
  }
  async writeln(input) {
    await this.write(input + "\n");
    return this;
  }
  sleep(ms) {
    return new Promise((res) => setTimeout(res, ms));
  }
  async close() {
    try {
      await this.writer.close();
    } catch (e) {
    }
  }
  async pipe(body) {
    this.writer.releaseLock();
    await body.pipeTo(this.writable, { preventClose: true });
    this.writer = this.writable.getWriter();
  }
  async onAbort(listener) {
    this.abortSubscribers.push(listener);
  }
};

// node_modules/hono/dist/context.js
var __accessCheck = (obj, member, msg) => {
  if (!member.has(obj))
    throw TypeError("Cannot " + msg);
};
var __privateGet = (obj, member, getter) => {
  __accessCheck(obj, member, "read from private field");
  return getter ? getter.call(obj) : member.get(obj);
};
var __privateAdd = (obj, member, value) => {
  if (member.has(obj))
    throw TypeError("Cannot add the same private member more than once");
  member instanceof WeakSet ? member.add(obj) : member.set(obj, value);
};
var __privateSet = (obj, member, value, setter) => {
  __accessCheck(obj, member, "write to private field");
  setter ? setter.call(obj, value) : member.set(obj, value);
  return value;
};
var TEXT_PLAIN = "text/plain; charset=UTF-8";
var setHeaders = (headers, map = {}) => {
  Object.entries(map).forEach(([key, value]) => headers.set(key, value));
  return headers;
};
var _status;
var _executionCtx;
var _headers;
var _preparedHeaders;
var _res;
var _isFresh;
var Context = class {
  constructor(req, options) {
    this.env = {};
    this._var = {};
    this.finalized = false;
    this.error = undefined;
    __privateAdd(this, _status, 200);
    __privateAdd(this, _executionCtx, undefined);
    __privateAdd(this, _headers, undefined);
    __privateAdd(this, _preparedHeaders, undefined);
    __privateAdd(this, _res, undefined);
    __privateAdd(this, _isFresh, true);
    this.renderer = (content) => this.html(content);
    this.notFoundHandler = () => new Response;
    this.render = (...args) => this.renderer(...args);
    this.setRenderer = (renderer) => {
      this.renderer = renderer;
    };
    this.header = (name, value, options2) => {
      if (value === undefined) {
        if (__privateGet(this, _headers)) {
          __privateGet(this, _headers).delete(name);
        } else if (__privateGet(this, _preparedHeaders)) {
          delete __privateGet(this, _preparedHeaders)[name.toLocaleLowerCase()];
        }
        if (this.finalized) {
          this.res.headers.delete(name);
        }
        return;
      }
      if (options2?.append) {
        if (!__privateGet(this, _headers)) {
          __privateSet(this, _isFresh, false);
          __privateSet(this, _headers, new Headers(__privateGet(this, _preparedHeaders)));
          __privateSet(this, _preparedHeaders, {});
        }
        __privateGet(this, _headers).append(name, value);
      } else {
        if (__privateGet(this, _headers)) {
          __privateGet(this, _headers).set(name, value);
        } else {
          __privateGet(this, _preparedHeaders) ?? __privateSet(this, _preparedHeaders, {});
          __privateGet(this, _preparedHeaders)[name.toLowerCase()] = value;
        }
      }
      if (this.finalized) {
        if (options2?.append) {
          this.res.headers.append(name, value);
        } else {
          this.res.headers.set(name, value);
        }
      }
    };
    this.status = (status) => {
      __privateSet(this, _isFresh, false);
      __privateSet(this, _status, status);
    };
    this.set = (key, value) => {
      this._var ?? (this._var = {});
      this._var[key] = value;
    };
    this.get = (key) => {
      return this._var ? this._var[key] : undefined;
    };
    this.newResponse = (data, arg, headers) => {
      if (__privateGet(this, _isFresh) && !headers && !arg && __privateGet(this, _status) === 200) {
        return new Response(data, {
          headers: __privateGet(this, _preparedHeaders)
        });
      }
      if (arg && typeof arg !== "number") {
        const headers2 = setHeaders(new Headers(arg.headers), __privateGet(this, _preparedHeaders));
        return new Response(data, {
          headers: headers2,
          status: arg.status
        });
      }
      const status = typeof arg === "number" ? arg : __privateGet(this, _status);
      __privateGet(this, _preparedHeaders) ?? __privateSet(this, _preparedHeaders, {});
      __privateGet(this, _headers) ?? __privateSet(this, _headers, new Headers);
      setHeaders(__privateGet(this, _headers), __privateGet(this, _preparedHeaders));
      if (__privateGet(this, _res)) {
        __privateGet(this, _res).headers.forEach((v, k) => {
          __privateGet(this, _headers)?.set(k, v);
        });
        setHeaders(__privateGet(this, _headers), __privateGet(this, _preparedHeaders));
      }
      headers ?? (headers = {});
      for (const [k, v] of Object.entries(headers)) {
        if (typeof v === "string") {
          __privateGet(this, _headers).set(k, v);
        } else {
          __privateGet(this, _headers).delete(k);
          for (const v2 of v) {
            __privateGet(this, _headers).append(k, v2);
          }
        }
      }
      return new Response(data, {
        status,
        headers: __privateGet(this, _headers)
      });
    };
    this.body = (data, arg, headers) => {
      return typeof arg === "number" ? this.newResponse(data, arg, headers) : this.newResponse(data, arg);
    };
    this.text = (text, arg, headers) => {
      if (!__privateGet(this, _preparedHeaders)) {
        if (__privateGet(this, _isFresh) && !headers && !arg) {
          return new Response(text);
        }
        __privateSet(this, _preparedHeaders, {});
      }
      __privateGet(this, _preparedHeaders)["content-type"] = TEXT_PLAIN;
      return typeof arg === "number" ? this.newResponse(text, arg, headers) : this.newResponse(text, arg);
    };
    this.json = (object, arg, headers) => {
      const body = JSON.stringify(object);
      __privateGet(this, _preparedHeaders) ?? __privateSet(this, _preparedHeaders, {});
      __privateGet(this, _preparedHeaders)["content-type"] = "application/json; charset=UTF-8";
      return typeof arg === "number" ? this.newResponse(body, arg, headers) : this.newResponse(body, arg);
    };
    this.jsonT = (object, arg, headers) => {
      return this.json(object, arg, headers);
    };
    this.html = (html4, arg, headers) => {
      __privateGet(this, _preparedHeaders) ?? __privateSet(this, _preparedHeaders, {});
      __privateGet(this, _preparedHeaders)["content-type"] = "text/html; charset=UTF-8";
      if (typeof html4 === "object") {
        if (!(html4 instanceof Promise)) {
          html4 = html4.toString();
        }
        if (html4 instanceof Promise) {
          return html4.then((html22) => resolveCallback(html22, HtmlEscapedCallbackPhase.Stringify, false, {})).then((html22) => {
            return typeof arg === "number" ? this.newResponse(html22, arg, headers) : this.newResponse(html22, arg);
          });
        }
      }
      return typeof arg === "number" ? this.newResponse(html4, arg, headers) : this.newResponse(html4, arg);
    };
    this.redirect = (location, status = 302) => {
      __privateGet(this, _headers) ?? __privateSet(this, _headers, new Headers);
      __privateGet(this, _headers).set("Location", location);
      return this.newResponse(null, status);
    };
    this.streamText = (cb, arg, headers) => {
      headers ?? (headers = {});
      this.header("content-type", TEXT_PLAIN);
      this.header("x-content-type-options", "nosniff");
      this.header("transfer-encoding", "chunked");
      return this.stream(cb, arg, headers);
    };
    this.stream = (cb, arg, headers) => {
      const { readable, writable } = new TransformStream;
      const stream2 = new StreamingApi(writable, readable);
      cb(stream2).finally(() => stream2.close());
      return typeof arg === "number" ? this.newResponse(stream2.responseReadable, arg, headers) : this.newResponse(stream2.responseReadable, arg);
    };
    this.cookie = (name, value, opt) => {
      const cookie2 = serialize(name, value, opt);
      this.header("set-cookie", cookie2, { append: true });
    };
    this.notFound = () => {
      return this.notFoundHandler(this);
    };
    this.req = req;
    if (options) {
      __privateSet(this, _executionCtx, options.executionCtx);
      this.env = options.env;
      if (options.notFoundHandler) {
        this.notFoundHandler = options.notFoundHandler;
      }
    }
  }
  get event() {
    if (__privateGet(this, _executionCtx) && "respondWith" in __privateGet(this, _executionCtx)) {
      return __privateGet(this, _executionCtx);
    } else {
      throw Error("This context has no FetchEvent");
    }
  }
  get executionCtx() {
    if (__privateGet(this, _executionCtx)) {
      return __privateGet(this, _executionCtx);
    } else {
      throw Error("This context has no ExecutionContext");
    }
  }
  get res() {
    __privateSet(this, _isFresh, false);
    return __privateGet(this, _res) || __privateSet(this, _res, new Response("404 Not Found", { status: 404 }));
  }
  set res(_res2) {
    __privateSet(this, _isFresh, false);
    if (__privateGet(this, _res) && _res2) {
      __privateGet(this, _res).headers.delete("content-type");
      for (const [k, v] of __privateGet(this, _res).headers.entries()) {
        if (k === "set-cookie") {
          const cookies = __privateGet(this, _res).headers.getSetCookie();
          _res2.headers.delete("set-cookie");
          for (const cookie2 of cookies) {
            _res2.headers.append("set-cookie", cookie2);
          }
        } else {
          _res2.headers.set(k, v);
        }
      }
    }
    __privateSet(this, _res, _res2);
    this.finalized = true;
  }
  get var() {
    return { ...this._var };
  }
  get runtime() {
    const global = globalThis;
    if (global?.Deno !== undefined) {
      return "deno";
    }
    if (global?.Bun !== undefined) {
      return "bun";
    }
    if (typeof global?.WebSocketPair === "function") {
      return "workerd";
    }
    if (typeof global?.EdgeRuntime === "string") {
      return "edge-light";
    }
    if (global?.fastly !== undefined) {
      return "fastly";
    }
    if (global?.__lagon__ !== undefined) {
      return "lagon";
    }
    if (global?.process?.release?.name === "node") {
      return "node";
    }
    return "other";
  }
};
_status = new WeakMap;
_executionCtx = new WeakMap;
_headers = new WeakMap;
_preparedHeaders = new WeakMap;
_res = new WeakMap;
_isFresh = new WeakMap;

// node_modules/hono/dist/compose.js
var compose = (middleware, onError, onNotFound) => {
  return (context2, next) => {
    let index = -1;
    return dispatch(0);
    async function dispatch(i) {
      if (i <= index) {
        throw new Error("next() called multiple times");
      }
      index = i;
      let res;
      let isError = false;
      let handler;
      if (middleware[i]) {
        handler = middleware[i][0][0];
        if (context2 instanceof Context) {
          context2.req.routeIndex = i;
        }
      } else {
        handler = i === middleware.length && next || undefined;
      }
      if (!handler) {
        if (context2 instanceof Context && context2.finalized === false && onNotFound) {
          res = await onNotFound(context2);
        }
      } else {
        try {
          res = await handler(context2, () => {
            return dispatch(i + 1);
          });
        } catch (err) {
          if (err instanceof Error && context2 instanceof Context && onError) {
            context2.error = err;
            res = await onError(err, context2);
            isError = true;
          } else {
            throw err;
          }
        }
      }
      if (res && (context2.finalized === false || isError)) {
        context2.res = res;
      }
      return context2;
    }
  };
};

// node_modules/hono/dist/http-exception.js
var HTTPException = class extends Error {
  constructor(status = 500, options) {
    super(options?.message);
    this.res = options?.res;
    this.status = status;
  }
  getResponse() {
    if (this.res) {
      return this.res;
    }
    return new Response(this.message, {
      status: this.status
    });
  }
};

// node_modules/hono/dist/utils/body.js
var isFormDataContent = function(contentType) {
  if (contentType === null) {
    return false;
  }
  return contentType.startsWith("multipart/form-data") || contentType.startsWith("application/x-www-form-urlencoded");
};
async function parseFormData(request, options) {
  const formData = await request.formData();
  if (formData) {
    return convertFormDataToBodyData(formData, options);
  }
  return {};
}
var convertFormDataToBodyData = function(formData, options) {
  const form = {};
  formData.forEach((value, key) => {
    const shouldParseAllValues = options.all || key.endsWith("[]");
    if (!shouldParseAllValues) {
      form[key] = value;
    } else {
      handleParsingAllValues(form, key, value);
    }
  });
  return form;
};
var isArrayField = function(field) {
  return Array.isArray(field);
};
var parseBody = async (request, options = { all: false }) => {
  const contentType = request.headers.get("Content-Type");
  if (isFormDataContent(contentType)) {
    return parseFormData(request, options);
  }
  return {};
};
var handleParsingAllValues = (form, key, value) => {
  if (form[key] && isArrayField(form[key])) {
    appendToExistingArray(form[key], value);
  } else if (form[key]) {
    convertToNewArray(form, key, value);
  } else {
    form[key] = value;
  }
};
var appendToExistingArray = (arr, value) => {
  arr.push(value);
};
var convertToNewArray = (form, key, value) => {
  form[key] = [form[key], value];
};

// node_modules/hono/dist/request.js
var __accessCheck2 = (obj, member, msg) => {
  if (!member.has(obj))
    throw TypeError("Cannot " + msg);
};
var __privateGet2 = (obj, member, getter) => {
  __accessCheck2(obj, member, "read from private field");
  return getter ? getter.call(obj) : member.get(obj);
};
var __privateAdd2 = (obj, member, value) => {
  if (member.has(obj))
    throw TypeError("Cannot add the same private member more than once");
  member instanceof WeakSet ? member.add(obj) : member.set(obj, value);
};
var __privateSet2 = (obj, member, value, setter) => {
  __accessCheck2(obj, member, "write to private field");
  setter ? setter.call(obj, value) : member.set(obj, value);
  return value;
};
var _validatedData;
var _matchResult;
var HonoRequest = class {
  constructor(request, path = "/", matchResult = [[]]) {
    __privateAdd2(this, _validatedData, undefined);
    __privateAdd2(this, _matchResult, undefined);
    this.routeIndex = 0;
    this.bodyCache = {};
    this.cachedBody = (key) => {
      const { bodyCache, raw: raw2 } = this;
      const cachedBody = bodyCache[key];
      if (cachedBody)
        return cachedBody;
      if (bodyCache.arrayBuffer) {
        return (async () => {
          return await new Response(bodyCache.arrayBuffer)[key]();
        })();
      }
      return bodyCache[key] = raw2[key]();
    };
    this.raw = request;
    this.path = path;
    __privateSet2(this, _matchResult, matchResult);
    __privateSet2(this, _validatedData, {});
  }
  param(key) {
    return key ? this.getDecodedParam(key) : this.getAllDecodedParams();
  }
  getDecodedParam(key) {
    const paramKey = __privateGet2(this, _matchResult)[0][this.routeIndex][1][key];
    const param = this.getParamValue(paramKey);
    return param ? /\%/.test(param) ? decodeURIComponent_(param) : param : undefined;
  }
  getAllDecodedParams() {
    const decoded = {};
    const keys = Object.keys(__privateGet2(this, _matchResult)[0][this.routeIndex][1]);
    for (const key of keys) {
      const value = this.getParamValue(__privateGet2(this, _matchResult)[0][this.routeIndex][1][key]);
      if (value && typeof value === "string") {
        decoded[key] = /\%/.test(value) ? decodeURIComponent_(value) : value;
      }
    }
    return decoded;
  }
  getParamValue(paramKey) {
    return __privateGet2(this, _matchResult)[1] ? __privateGet2(this, _matchResult)[1][paramKey] : paramKey;
  }
  query(key) {
    return getQueryParam(this.url, key);
  }
  queries(key) {
    return getQueryParams(this.url, key);
  }
  header(name) {
    if (name)
      return this.raw.headers.get(name.toLowerCase()) ?? undefined;
    const headerData = {};
    this.raw.headers.forEach((value, key) => {
      headerData[key] = value;
    });
    return headerData;
  }
  cookie(key) {
    const cookie3 = this.raw.headers.get("Cookie");
    if (!cookie3)
      return;
    const obj = parse(cookie3);
    if (key) {
      const value = obj[key];
      return value;
    } else {
      return obj;
    }
  }
  async parseBody(options) {
    if (this.bodyCache.parsedBody)
      return this.bodyCache.parsedBody;
    const parsedBody = await parseBody(this, options);
    this.bodyCache.parsedBody = parsedBody;
    return parsedBody;
  }
  json() {
    return this.cachedBody("json");
  }
  text() {
    return this.cachedBody("text");
  }
  arrayBuffer() {
    return this.cachedBody("arrayBuffer");
  }
  blob() {
    return this.cachedBody("blob");
  }
  formData() {
    return this.cachedBody("formData");
  }
  addValidatedData(target, data) {
    __privateGet2(this, _validatedData)[target] = data;
  }
  valid(target) {
    return __privateGet2(this, _validatedData)[target];
  }
  get url() {
    return this.raw.url;
  }
  get method() {
    return this.raw.method;
  }
  get matchedRoutes() {
    return __privateGet2(this, _matchResult)[0].map(([[, route]]) => route);
  }
  get routePath() {
    return __privateGet2(this, _matchResult)[0].map(([[, route]]) => route)[this.routeIndex].path;
  }
  get headers() {
    return this.raw.headers;
  }
  get body() {
    return this.raw.body;
  }
  get bodyUsed() {
    return this.raw.bodyUsed;
  }
  get integrity() {
    return this.raw.integrity;
  }
  get keepalive() {
    return this.raw.keepalive;
  }
  get referrer() {
    return this.raw.referrer;
  }
  get signal() {
    return this.raw.signal;
  }
};
_validatedData = new WeakMap;
_matchResult = new WeakMap;

// node_modules/hono/dist/router.js
var METHOD_NAME_ALL = "ALL";
var METHOD_NAME_ALL_LOWERCASE = "all";
var METHODS = ["get", "post", "put", "delete", "options", "patch"];
var MESSAGE_MATCHER_IS_ALREADY_BUILT = "Can not add a route since the matcher is already built.";
var UnsupportedPathError = class extends Error {
};

// node_modules/hono/dist/hono-base.js
var defineDynamicClass = function() {
  return class {
  };
};
var __accessCheck3 = (obj, member, msg) => {
  if (!member.has(obj))
    throw TypeError("Cannot " + msg);
};
var __privateGet3 = (obj, member, getter) => {
  __accessCheck3(obj, member, "read from private field");
  return getter ? getter.call(obj) : member.get(obj);
};
var __privateAdd3 = (obj, member, value) => {
  if (member.has(obj))
    throw TypeError("Cannot add the same private member more than once");
  member instanceof WeakSet ? member.add(obj) : member.set(obj, value);
};
var __privateSet3 = (obj, member, value, setter) => {
  __accessCheck3(obj, member, "write to private field");
  setter ? setter.call(obj, value) : member.set(obj, value);
  return value;
};
var COMPOSED_HANDLER = Symbol("composedHandler");
var notFoundHandler = (c) => {
  return c.text("404 Not Found", 404);
};
var errorHandler = (err, c) => {
  if (err instanceof HTTPException) {
    return err.getResponse();
  }
  console.error(err);
  const message = "Internal Server Error";
  return c.text(message, 500);
};
var _path;
var _Hono = class extends defineDynamicClass() {
  constructor(options = {}) {
    super();
    this._basePath = "/";
    __privateAdd3(this, _path, "/");
    this.routes = [];
    this.notFoundHandler = notFoundHandler;
    this.errorHandler = errorHandler;
    this.onError = (handler) => {
      this.errorHandler = handler;
      return this;
    };
    this.notFound = (handler) => {
      this.notFoundHandler = handler;
      return this;
    };
    this.head = () => {
      console.warn("`app.head()` is no longer used. `app.get()` implicitly handles the HEAD method.");
      return this;
    };
    this.handleEvent = (event) => {
      return this.dispatch(event.request, event, undefined, event.request.method);
    };
    this.fetch = (request2, Env, executionCtx) => {
      return this.dispatch(request2, executionCtx, Env, request2.method);
    };
    this.request = (input, requestInit, Env, executionCtx) => {
      if (input instanceof Request) {
        if (requestInit !== undefined) {
          input = new Request(input, requestInit);
        }
        return this.fetch(input, Env, executionCtx);
      }
      input = input.toString();
      const path = /^https?:\/\//.test(input) ? input : `http://localhost${mergePath("/", input)}`;
      const req = new Request(path, requestInit);
      return this.fetch(req, Env, executionCtx);
    };
    this.fire = () => {
      addEventListener("fetch", (event) => {
        event.respondWith(this.dispatch(event.request, event, undefined, event.request.method));
      });
    };
    const allMethods = [...METHODS, METHOD_NAME_ALL_LOWERCASE];
    allMethods.map((method) => {
      this[method] = (args1, ...args) => {
        if (typeof args1 === "string") {
          __privateSet3(this, _path, args1);
        } else {
          this.addRoute(method, __privateGet3(this, _path), args1);
        }
        args.map((handler) => {
          if (typeof handler !== "string") {
            this.addRoute(method, __privateGet3(this, _path), handler);
          }
        });
        return this;
      };
    });
    this.on = (method, path, ...handlers) => {
      if (!method)
        return this;
      __privateSet3(this, _path, path);
      for (const m of [method].flat()) {
        handlers.map((handler) => {
          this.addRoute(m.toUpperCase(), __privateGet3(this, _path), handler);
        });
      }
      return this;
    };
    this.use = (arg1, ...handlers) => {
      if (typeof arg1 === "string") {
        __privateSet3(this, _path, arg1);
      } else {
        handlers.unshift(arg1);
      }
      handlers.map((handler) => {
        this.addRoute(METHOD_NAME_ALL, __privateGet3(this, _path), handler);
      });
      return this;
    };
    const strict = options.strict ?? true;
    delete options.strict;
    Object.assign(this, options);
    this.getPath = strict ? options.getPath ?? getPath : getPathNoStrict;
  }
  clone() {
    const clone = new _Hono({
      router: this.router,
      getPath: this.getPath
    });
    clone.routes = this.routes;
    return clone;
  }
  route(path, app) {
    const subApp = this.basePath(path);
    if (!app) {
      return subApp;
    }
    app.routes.map((r) => {
      let handler;
      if (app.errorHandler === errorHandler) {
        handler = r.handler;
      } else {
        handler = async (c, next) => (await compose([], app.errorHandler)(c, () => r.handler(c, next))).res;
        handler[COMPOSED_HANDLER] = r.handler;
      }
      subApp.addRoute(r.method, r.path, handler);
    });
    return this;
  }
  basePath(path) {
    const subApp = this.clone();
    subApp._basePath = mergePath(this._basePath, path);
    return subApp;
  }
  showRoutes() {
    const length = 8;
    this.routes.map((route) => {
      console.log(`\x1B[32m${route.method}\x1B[0m ${" ".repeat(length - route.method.length)} ${route.path}`);
    });
  }
  mount(path, applicationHandler, optionHandler) {
    const mergedPath = mergePath(this._basePath, path);
    const pathPrefixLength = mergedPath === "/" ? 0 : mergedPath.length;
    const handler = async (c, next) => {
      let executionContext = undefined;
      try {
        executionContext = c.executionCtx;
      } catch {
      }
      const options = optionHandler ? optionHandler(c) : [c.env, executionContext];
      const optionsArray = Array.isArray(options) ? options : [options];
      const queryStrings = getQueryStrings(c.req.url);
      const res = await applicationHandler(new Request(new URL((c.req.path.slice(pathPrefixLength) || "/") + queryStrings, c.req.url), c.req.raw), ...optionsArray);
      if (res)
        return res;
      await next();
    };
    this.addRoute(METHOD_NAME_ALL, mergePath(path, "*"), handler);
    return this;
  }
  get routerName() {
    this.matchRoute("GET", "/");
    return this.router.name;
  }
  addRoute(method, path, handler) {
    method = method.toUpperCase();
    path = mergePath(this._basePath, path);
    const r = { path, method, handler };
    this.router.add(method, path, [handler, r]);
    this.routes.push(r);
  }
  matchRoute(method, path) {
    return this.router.match(method, path);
  }
  handleError(err, c) {
    if (err instanceof Error) {
      return this.errorHandler(err, c);
    }
    throw err;
  }
  dispatch(request2, executionCtx, env, method) {
    if (method === "HEAD") {
      return (async () => new Response(null, await this.dispatch(request2, executionCtx, env, "GET")))();
    }
    const path = this.getPath(request2, { env });
    const matchResult = this.matchRoute(method, path);
    const c = new Context(new HonoRequest(request2, path, matchResult), {
      env,
      executionCtx,
      notFoundHandler: this.notFoundHandler
    });
    if (matchResult[0].length === 1) {
      let res;
      try {
        res = matchResult[0][0][0][0](c, async () => {
          c.res = await this.notFoundHandler(c);
        });
      } catch (err) {
        return this.handleError(err, c);
      }
      return res instanceof Promise ? res.then((resolved) => resolved || (c.finalized ? c.res : this.notFoundHandler(c))).catch((err) => this.handleError(err, c)) : res;
    }
    const composed = compose(matchResult[0], this.errorHandler, this.notFoundHandler);
    return (async () => {
      try {
        const context3 = await composed(c);
        if (!context3.finalized) {
          throw new Error("Context is not finalized. You may forget returning Response object or `await next()`");
        }
        return context3.res;
      } catch (err) {
        return this.handleError(err, c);
      }
    })();
  }
};
var Hono = _Hono;
_path = new WeakMap;

// node_modules/hono/dist/router/reg-exp-router/node.js
var compareKey = function(a, b) {
  if (a.length === 1) {
    return b.length === 1 ? a < b ? -1 : 1 : -1;
  }
  if (b.length === 1) {
    return 1;
  }
  if (a === ONLY_WILDCARD_REG_EXP_STR || a === TAIL_WILDCARD_REG_EXP_STR) {
    return 1;
  } else if (b === ONLY_WILDCARD_REG_EXP_STR || b === TAIL_WILDCARD_REG_EXP_STR) {
    return -1;
  }
  if (a === LABEL_REG_EXP_STR) {
    return 1;
  } else if (b === LABEL_REG_EXP_STR) {
    return -1;
  }
  return a.length === b.length ? a < b ? -1 : 1 : b.length - a.length;
};
var LABEL_REG_EXP_STR = "[^/]+";
var ONLY_WILDCARD_REG_EXP_STR = ".*";
var TAIL_WILDCARD_REG_EXP_STR = "(?:|/.*)";
var PATH_ERROR = Symbol();
var Node = class {
  constructor() {
    this.children = {};
  }
  insert(tokens, index, paramMap, context3, pathErrorCheckOnly) {
    if (tokens.length === 0) {
      if (this.index !== undefined) {
        throw PATH_ERROR;
      }
      if (pathErrorCheckOnly) {
        return;
      }
      this.index = index;
      return;
    }
    const [token, ...restTokens] = tokens;
    const pattern = token === "*" ? restTokens.length === 0 ? ["", "", ONLY_WILDCARD_REG_EXP_STR] : ["", "", LABEL_REG_EXP_STR] : token === "/*" ? ["", "", TAIL_WILDCARD_REG_EXP_STR] : token.match(/^\:([^\{\}]+)(?:\{(.+)\})?$/);
    let node;
    if (pattern) {
      const name = pattern[1];
      let regexpStr = pattern[2] || LABEL_REG_EXP_STR;
      if (name && pattern[2]) {
        regexpStr = regexpStr.replace(/^\((?!\?:)(?=[^)]+\)$)/, "(?:");
        if (/\((?!\?:)/.test(regexpStr)) {
          throw PATH_ERROR;
        }
      }
      node = this.children[regexpStr];
      if (!node) {
        if (Object.keys(this.children).some((k) => k !== ONLY_WILDCARD_REG_EXP_STR && k !== TAIL_WILDCARD_REG_EXP_STR)) {
          throw PATH_ERROR;
        }
        if (pathErrorCheckOnly) {
          return;
        }
        node = this.children[regexpStr] = new Node;
        if (name !== "") {
          node.varIndex = context3.varIndex++;
        }
      }
      if (!pathErrorCheckOnly && name !== "") {
        paramMap.push([name, node.varIndex]);
      }
    } else {
      node = this.children[token];
      if (!node) {
        if (Object.keys(this.children).some((k) => k.length > 1 && k !== ONLY_WILDCARD_REG_EXP_STR && k !== TAIL_WILDCARD_REG_EXP_STR)) {
          throw PATH_ERROR;
        }
        if (pathErrorCheckOnly) {
          return;
        }
        node = this.children[token] = new Node;
      }
    }
    node.insert(restTokens, index, paramMap, context3, pathErrorCheckOnly);
  }
  buildRegExpStr() {
    const childKeys = Object.keys(this.children).sort(compareKey);
    const strList = childKeys.map((k) => {
      const c = this.children[k];
      return (typeof c.varIndex === "number" ? `(${k})@${c.varIndex}` : k) + c.buildRegExpStr();
    });
    if (typeof this.index === "number") {
      strList.unshift(`#${this.index}`);
    }
    if (strList.length === 0) {
      return "";
    }
    if (strList.length === 1) {
      return strList[0];
    }
    return "(?:" + strList.join("|") + ")";
  }
};

// node_modules/hono/dist/router/reg-exp-router/trie.js
var Trie = class {
  constructor() {
    this.context = { varIndex: 0 };
    this.root = new Node;
  }
  insert(path, index, pathErrorCheckOnly) {
    const paramAssoc = [];
    const groups = [];
    for (let i = 0;; ) {
      let replaced = false;
      path = path.replace(/\{[^}]+\}/g, (m) => {
        const mark = `@\\${i}`;
        groups[i] = [mark, m];
        i++;
        replaced = true;
        return mark;
      });
      if (!replaced) {
        break;
      }
    }
    const tokens = path.match(/(?::[^\/]+)|(?:\/\*$)|./g) || [];
    for (let i = groups.length - 1;i >= 0; i--) {
      const [mark] = groups[i];
      for (let j = tokens.length - 1;j >= 0; j--) {
        if (tokens[j].indexOf(mark) !== -1) {
          tokens[j] = tokens[j].replace(mark, groups[i][1]);
          break;
        }
      }
    }
    this.root.insert(tokens, index, paramAssoc, this.context, pathErrorCheckOnly);
    return paramAssoc;
  }
  buildRegExp() {
    let regexp = this.root.buildRegExpStr();
    if (regexp === "") {
      return [/^$/, [], []];
    }
    let captureIndex = 0;
    const indexReplacementMap = [];
    const paramReplacementMap = [];
    regexp = regexp.replace(/#(\d+)|@(\d+)|\.\*\$/g, (_, handlerIndex, paramIndex) => {
      if (typeof handlerIndex !== "undefined") {
        indexReplacementMap[++captureIndex] = Number(handlerIndex);
        return "$()";
      }
      if (typeof paramIndex !== "undefined") {
        paramReplacementMap[Number(paramIndex)] = ++captureIndex;
        return "";
      }
      return "";
    });
    return [new RegExp(`^${regexp}`), indexReplacementMap, paramReplacementMap];
  }
};

// node_modules/hono/dist/router/reg-exp-router/router.js
var buildWildcardRegExp = function(path) {
  return wildcardRegExpCache[path] ?? (wildcardRegExpCache[path] = new RegExp(path === "*" ? "" : `^${path.replace(/\/\*/, "(?:|/.*)")}\$`));
};
var clearWildcardRegExpCache = function() {
  wildcardRegExpCache = {};
};
var buildMatcherFromPreprocessedRoutes = function(routes) {
  const trie2 = new Trie;
  const handlerData = [];
  if (routes.length === 0) {
    return nullMatcher;
  }
  const routesWithStaticPathFlag = routes.map((route) => [!/\*|\/:/.test(route[0]), ...route]).sort(([isStaticA, pathA], [isStaticB, pathB]) => isStaticA ? 1 : isStaticB ? -1 : pathA.length - pathB.length);
  const staticMap = {};
  for (let i = 0, j = -1, len = routesWithStaticPathFlag.length;i < len; i++) {
    const [pathErrorCheckOnly, path, handlers] = routesWithStaticPathFlag[i];
    if (pathErrorCheckOnly) {
      staticMap[path] = [handlers.map(([h]) => [h, {}]), emptyParam];
    } else {
      j++;
    }
    let paramAssoc;
    try {
      paramAssoc = trie2.insert(path, j, pathErrorCheckOnly);
    } catch (e) {
      throw e === PATH_ERROR ? new UnsupportedPathError(path) : e;
    }
    if (pathErrorCheckOnly) {
      continue;
    }
    handlerData[j] = handlers.map(([h, paramCount]) => {
      const paramIndexMap = {};
      paramCount -= 1;
      for (;paramCount >= 0; paramCount--) {
        const [key, value] = paramAssoc[paramCount];
        paramIndexMap[key] = value;
      }
      return [h, paramIndexMap];
    });
  }
  const [regexp, indexReplacementMap, paramReplacementMap] = trie2.buildRegExp();
  for (let i = 0, len = handlerData.length;i < len; i++) {
    for (let j = 0, len2 = handlerData[i].length;j < len2; j++) {
      const map = handlerData[i][j]?.[1];
      if (!map) {
        continue;
      }
      const keys = Object.keys(map);
      for (let k = 0, len3 = keys.length;k < len3; k++) {
        map[keys[k]] = paramReplacementMap[map[keys[k]]];
      }
    }
  }
  const handlerMap = [];
  for (const i in indexReplacementMap) {
    handlerMap[i] = handlerData[indexReplacementMap[i]];
  }
  return [regexp, handlerMap, staticMap];
};
var findMiddleware = function(middleware, path) {
  if (!middleware) {
    return;
  }
  for (const k of Object.keys(middleware).sort((a, b) => b.length - a.length)) {
    if (buildWildcardRegExp(k).test(path)) {
      return [...middleware[k]];
    }
  }
  return;
};
var methodNames = [METHOD_NAME_ALL, ...METHODS].map((method) => method.toUpperCase());
var emptyParam = [];
var nullMatcher = [/^$/, [], {}];
var wildcardRegExpCache = {};
var RegExpRouter = class {
  constructor() {
    this.name = "RegExpRouter";
    this.middleware = { [METHOD_NAME_ALL]: {} };
    this.routes = { [METHOD_NAME_ALL]: {} };
  }
  add(method, path, handler) {
    var _a;
    const { middleware, routes } = this;
    if (!middleware || !routes) {
      throw new Error(MESSAGE_MATCHER_IS_ALREADY_BUILT);
    }
    if (methodNames.indexOf(method) === -1)
      methodNames.push(method);
    if (!middleware[method]) {
      [middleware, routes].forEach((handlerMap) => {
        handlerMap[method] = {};
        Object.keys(handlerMap[METHOD_NAME_ALL]).forEach((p) => {
          handlerMap[method][p] = [...handlerMap[METHOD_NAME_ALL][p]];
        });
      });
    }
    if (path === "/*") {
      path = "*";
    }
    const paramCount = (path.match(/\/:/g) || []).length;
    if (/\*$/.test(path)) {
      const re = buildWildcardRegExp(path);
      if (method === METHOD_NAME_ALL) {
        Object.keys(middleware).forEach((m) => {
          var _a2;
          (_a2 = middleware[m])[path] || (_a2[path] = findMiddleware(middleware[m], path) || findMiddleware(middleware[METHOD_NAME_ALL], path) || []);
        });
      } else {
        (_a = middleware[method])[path] || (_a[path] = findMiddleware(middleware[method], path) || findMiddleware(middleware[METHOD_NAME_ALL], path) || []);
      }
      Object.keys(middleware).forEach((m) => {
        if (method === METHOD_NAME_ALL || method === m) {
          Object.keys(middleware[m]).forEach((p) => {
            re.test(p) && middleware[m][p].push([handler, paramCount]);
          });
        }
      });
      Object.keys(routes).forEach((m) => {
        if (method === METHOD_NAME_ALL || method === m) {
          Object.keys(routes[m]).forEach((p) => re.test(p) && routes[m][p].push([handler, paramCount]));
        }
      });
      return;
    }
    const paths = checkOptionalParameter(path) || [path];
    for (let i = 0, len = paths.length;i < len; i++) {
      const path2 = paths[i];
      Object.keys(routes).forEach((m) => {
        var _a2;
        if (method === METHOD_NAME_ALL || method === m) {
          (_a2 = routes[m])[path2] || (_a2[path2] = [
            ...findMiddleware(middleware[m], path2) || findMiddleware(middleware[METHOD_NAME_ALL], path2) || []
          ]);
          routes[m][path2].push([handler, paramCount - len + i + 1]);
        }
      });
    }
  }
  match(method, path) {
    clearWildcardRegExpCache();
    const matchers = this.buildAllMatchers();
    this.match = (method2, path2) => {
      const matcher = matchers[method2];
      const staticMatch = matcher[2][path2];
      if (staticMatch) {
        return staticMatch;
      }
      const match = path2.match(matcher[0]);
      if (!match) {
        return [[], emptyParam];
      }
      const index = match.indexOf("", 1);
      return [matcher[1][index], match];
    };
    return this.match(method, path);
  }
  buildAllMatchers() {
    const matchers = {};
    methodNames.forEach((method) => {
      matchers[method] = this.buildMatcher(method) || matchers[METHOD_NAME_ALL];
    });
    this.middleware = this.routes = undefined;
    return matchers;
  }
  buildMatcher(method) {
    const routes = [];
    let hasOwnRoute = method === METHOD_NAME_ALL;
    [this.middleware, this.routes].forEach((r) => {
      const ownRoute = r[method] ? Object.keys(r[method]).map((path) => [path, r[method][path]]) : [];
      if (ownRoute.length !== 0) {
        hasOwnRoute || (hasOwnRoute = true);
        routes.push(...ownRoute);
      } else if (method !== METHOD_NAME_ALL) {
        routes.push(...Object.keys(r[METHOD_NAME_ALL]).map((path) => [path, r[METHOD_NAME_ALL][path]]));
      }
    });
    if (!hasOwnRoute) {
      return null;
    } else {
      return buildMatcherFromPreprocessedRoutes(routes);
    }
  }
};

// node_modules/hono/dist/router/smart-router/router.js
var SmartRouter = class {
  constructor(init) {
    this.name = "SmartRouter";
    this.routers = [];
    this.routes = [];
    Object.assign(this, init);
  }
  add(method, path, handler) {
    if (!this.routes) {
      throw new Error(MESSAGE_MATCHER_IS_ALREADY_BUILT);
    }
    this.routes.push([method, path, handler]);
  }
  match(method, path) {
    if (!this.routes) {
      throw new Error("Fatal error");
    }
    const { routers, routes } = this;
    const len = routers.length;
    let i = 0;
    let res;
    for (;i < len; i++) {
      const router5 = routers[i];
      try {
        routes.forEach((args) => {
          router5.add(...args);
        });
        res = router5.match(method, path);
      } catch (e) {
        if (e instanceof UnsupportedPathError) {
          continue;
        }
        throw e;
      }
      this.match = router5.match.bind(router5);
      this.routers = [router5];
      this.routes = undefined;
      break;
    }
    if (i === len) {
      throw new Error("Fatal error");
    }
    this.name = `SmartRouter + ${this.activeRouter.name}`;
    return res;
  }
  get activeRouter() {
    if (this.routes || this.routers.length !== 1) {
      throw new Error("No active router has been determined yet.");
    }
    return this.routers[0];
  }
};

// node_modules/hono/dist/router/trie-router/node.js
var Node2 = class {
  constructor(method, handler, children) {
    this.order = 0;
    this.params = {};
    this.children = children || {};
    this.methods = [];
    this.name = "";
    if (method && handler) {
      const m = {};
      m[method] = { handler, possibleKeys: [], score: 0, name: this.name };
      this.methods = [m];
    }
    this.patterns = [];
  }
  insert(method, path, handler) {
    this.name = `${method} ${path}`;
    this.order = ++this.order;
    let curNode = this;
    const parts = splitRoutingPath(path);
    const possibleKeys = [];
    const parentPatterns = [];
    for (let i = 0, len = parts.length;i < len; i++) {
      const p = parts[i];
      if (Object.keys(curNode.children).includes(p)) {
        parentPatterns.push(...curNode.patterns);
        curNode = curNode.children[p];
        const pattern2 = getPattern(p);
        if (pattern2)
          possibleKeys.push(pattern2[1]);
        continue;
      }
      curNode.children[p] = new Node2;
      const pattern = getPattern(p);
      if (pattern) {
        curNode.patterns.push(pattern);
        parentPatterns.push(...curNode.patterns);
        possibleKeys.push(pattern[1]);
      }
      parentPatterns.push(...curNode.patterns);
      curNode = curNode.children[p];
    }
    if (!curNode.methods.length) {
      curNode.methods = [];
    }
    const m = {};
    const handlerSet = {
      handler,
      possibleKeys: possibleKeys.filter((v, i, a) => a.indexOf(v) === i),
      name: this.name,
      score: this.order
    };
    m[method] = handlerSet;
    curNode.methods.push(m);
    return curNode;
  }
  gHSets(node3, method, nodeParams, params) {
    const handlerSets = [];
    for (let i = 0, len = node3.methods.length;i < len; i++) {
      const m = node3.methods[i];
      const handlerSet = m[method] || m[METHOD_NAME_ALL];
      const processedSet = {};
      if (handlerSet !== undefined) {
        handlerSet.params = {};
        handlerSet.possibleKeys.forEach((key) => {
          const processed = processedSet[handlerSet.name];
          handlerSet.params[key] = params[key] && !processed ? params[key] : nodeParams[key] ?? params[key];
          processedSet[handlerSet.name] = true;
        });
        handlerSets.push(handlerSet);
      }
    }
    return handlerSets;
  }
  search(method, path) {
    const handlerSets = [];
    this.params = {};
    const params = {};
    const curNode = this;
    let curNodes = [curNode];
    const parts = splitPath(path);
    for (let i = 0, len = parts.length;i < len; i++) {
      const part = parts[i];
      const isLast = i === len - 1;
      const tempNodes = [];
      for (let j = 0, len2 = curNodes.length;j < len2; j++) {
        const node3 = curNodes[j];
        const nextNode = node3.children[part];
        if (nextNode) {
          nextNode.params = node3.params;
          if (isLast === true) {
            if (nextNode.children["*"]) {
              handlerSets.push(...this.gHSets(nextNode.children["*"], method, node3.params, {}));
            }
            handlerSets.push(...this.gHSets(nextNode, method, node3.params, {}));
          } else {
            tempNodes.push(nextNode);
          }
        }
        for (let k = 0, len3 = node3.patterns.length;k < len3; k++) {
          const pattern = node3.patterns[k];
          if (pattern === "*") {
            const astNode = node3.children["*"];
            if (astNode) {
              handlerSets.push(...this.gHSets(astNode, method, node3.params, {}));
              tempNodes.push(astNode);
            }
            continue;
          }
          if (part === "")
            continue;
          const [key, name, matcher] = pattern;
          const child = node3.children[key];
          const restPathString = parts.slice(i).join("/");
          if (matcher instanceof RegExp && matcher.test(restPathString)) {
            params[name] = restPathString;
            handlerSets.push(...this.gHSets(child, method, node3.params, params));
            continue;
          }
          if (matcher === true || matcher instanceof RegExp && matcher.test(part)) {
            if (typeof key === "string") {
              params[name] = part;
              if (isLast === true) {
                handlerSets.push(...this.gHSets(child, method, params, node3.params));
                if (child.children["*"]) {
                  handlerSets.push(...this.gHSets(child.children["*"], method, node3.params, params));
                }
              } else {
                child.params = { ...params };
                tempNodes.push(child);
              }
            }
          }
        }
      }
      curNodes = tempNodes;
    }
    const results = handlerSets.sort((a, b) => {
      return a.score - b.score;
    });
    return [results.map(({ handler, params: params2 }) => [handler, params2])];
  }
};

// node_modules/hono/dist/router/trie-router/router.js
var TrieRouter = class {
  constructor() {
    this.name = "TrieRouter";
    this.node = new Node2;
  }
  add(method, path, handler) {
    const results = checkOptionalParameter(path);
    if (results) {
      for (const p of results) {
        this.node.insert(method, p, handler);
      }
      return;
    }
    this.node.insert(method, path, handler);
  }
  match(method, path) {
    return this.node.search(method, path);
  }
};

// node_modules/hono/dist/hono.js
var Hono2 = class extends Hono {
  constructor(options = {}) {
    super(options);
    this.router = options.router ?? new SmartRouter({
      routers: [new RegExpRouter, new TrieRouter]
    });
  }
};

// node_modules/hono/dist/middleware/cors/index.js
var cors = (options) => {
  const defaults = {
    origin: "*",
    allowMethods: ["GET", "HEAD", "PUT", "POST", "DELETE", "PATCH"],
    allowHeaders: [],
    exposeHeaders: []
  };
  const opts = {
    ...defaults,
    ...options
  };
  const findAllowOrigin = ((optsOrigin) => {
    if (typeof optsOrigin === "string") {
      return () => optsOrigin;
    } else if (typeof optsOrigin === "function") {
      return optsOrigin;
    } else {
      return (origin) => optsOrigin.includes(origin) ? origin : optsOrigin[0];
    }
  })(opts.origin);
  return async function cors2(c, next) {
    function set(key, value) {
      c.res.headers.set(key, value);
    }
    const allowOrigin = findAllowOrigin(c.req.header("origin") || "");
    if (allowOrigin) {
      set("Access-Control-Allow-Origin", allowOrigin);
    }
    if (opts.origin !== "*") {
      set("Vary", "Origin");
    }
    if (opts.credentials) {
      set("Access-Control-Allow-Credentials", "true");
    }
    if (opts.exposeHeaders?.length) {
      set("Access-Control-Expose-Headers", opts.exposeHeaders.join(","));
    }
    if (c.req.method === "OPTIONS") {
      if (opts.maxAge != null) {
        set("Access-Control-Max-Age", opts.maxAge.toString());
      }
      if (opts.allowMethods?.length) {
        set("Access-Control-Allow-Methods", opts.allowMethods.join(","));
      }
      let headers = opts.allowHeaders;
      if (!headers?.length) {
        const requestHeaders = c.req.header("Access-Control-Request-Headers");
        if (requestHeaders) {
          headers = requestHeaders.split(/\s*,\s*/);
        }
      }
      if (headers?.length) {
        set("Access-Control-Allow-Headers", headers.join(","));
        c.res.headers.append("Vary", "Access-Control-Request-Headers");
      }
      c.res.headers.delete("Content-Length");
      c.res.headers.delete("Content-Type");
      return new Response(null, {
        headers: c.res.headers,
        status: 204,
        statusText: c.res.statusText
      });
    }
    await next();
  };
};

// node_modules/@planetscale/database/dist/sanitization.js
function format(query, values) {
  return Array.isArray(values) ? replacePosition(query, values) : replaceNamed(query, values);
}
var replacePosition = function(query, values) {
  let index = 0;
  return query.replace(/\?/g, (match) => {
    return index < values.length ? sanitize(values[index++]) : match;
  });
};
var replaceNamed = function(query, values) {
  return query.replace(/:(\w+)/g, (match, name) => {
    return hasOwn(values, name) ? sanitize(values[name]) : match;
  });
};
var hasOwn = function(obj, name) {
  return Object.prototype.hasOwnProperty.call(obj, name);
};
var sanitize = function(value) {
  if (value == null) {
    return "null";
  }
  if (["number", "bigint"].includes(typeof value)) {
    return String(value);
  }
  if (typeof value === "boolean") {
    return value ? "true" : "false";
  }
  if (typeof value === "string") {
    return quote(value);
  }
  if (Array.isArray(value)) {
    return value.map(sanitize).join(", ");
  }
  if (value instanceof Date) {
    return quote(value.toISOString().slice(0, -1));
  }
  return quote(value.toString());
};
var quote = function(text) {
  return `'${escape(text)}'`;
};
var escape = function(text) {
  return text.replace(re, replacement);
};
var replacement = function(text) {
  switch (text) {
    case '"':
      return '\\"';
    case "'":
      return "\\'";
    case "\n":
      return "\\n";
    case "\r":
      return "\\r";
    case "\t":
      return "\\t";
    case "\\":
      return "\\\\";
    case "\0":
      return "\\0";
    case "\b":
      return "\\b";
    case "\x1A":
      return "\\Z";
    default:
      return "";
  }
};
var re = /[\0\b\n\r\t\x1a\\"']/g;
// node_modules/@planetscale/database/dist/text.js
function decode(text) {
  return text ? decoder.decode(Uint8Array.from(bytes(text))) : "";
}
var bytes = function(text) {
  return text.split("").map((c) => c.charCodeAt(0));
};
var decoder = new TextDecoder("utf-8");
// node_modules/@planetscale/database/dist/version.js
var Version = "1.14.0";

// node_modules/@planetscale/database/dist/index.js
var protocol = function(protocol2) {
  return protocol2 === "http:" ? protocol2 : "https:";
};
var buildURL = function(url7) {
  const scheme = `${protocol(url7.protocol)}//`;
  return new URL(url7.pathname, `${scheme}${url7.host}`).toString();
};
async function postJSON(config, url7, body2 = {}) {
  const auth = btoa(`${config.username}:${config.password}`);
  const { fetch: fetch2 } = config;
  const response = await fetch2(url7.toString(), {
    method: "POST",
    body: JSON.stringify(body2),
    headers: {
      "Content-Type": "application/json",
      "User-Agent": `database-js/${Version}`,
      Authorization: `Basic ${auth}`
    },
    cache: "no-store"
  });
  if (response.ok) {
    return await response.json();
  } else {
    let error = null;
    try {
      const e = (await response.json()).error;
      error = new DatabaseError(e.message, response.status, e);
    } catch {
      error = new DatabaseError(response.statusText, response.status, {
        code: "internal",
        message: response.statusText
      });
    }
    throw error;
  }
}
var parseArrayRow = function(fields, rawRow, cast) {
  const row = decodeRow(rawRow);
  return fields.map((field, ix) => {
    return cast(field, row[ix]);
  });
};
var parseObjectRow = function(fields, rawRow, cast) {
  const row = decodeRow(rawRow);
  return fields.reduce((acc, field, ix) => {
    acc[field.name] = cast(field, row[ix]);
    return acc;
  }, {});
};
var parse2 = function(result, cast, returnAs) {
  const fields = result.fields;
  const rows = result.rows ?? [];
  return rows.map((row) => returnAs === "array" ? parseArrayRow(fields, row, cast) : parseObjectRow(fields, row, cast));
};
var decodeRow = function(row) {
  const values = row.values ? atob(row.values) : "";
  let offset = 0;
  return row.lengths.map((size) => {
    const width = parseInt(size, 10);
    if (width < 0)
      return null;
    const splice = values.substring(offset, offset + width);
    offset += width;
    return splice;
  });
};
function cast(field, value) {
  if (value === "" || value == null) {
    return value;
  }
  switch (field.type) {
    case "INT8":
    case "INT16":
    case "INT24":
    case "INT32":
    case "UINT8":
    case "UINT16":
    case "UINT24":
    case "UINT32":
    case "YEAR":
      return parseInt(value, 10);
    case "FLOAT32":
    case "FLOAT64":
      return parseFloat(value);
    case "DECIMAL":
    case "INT64":
    case "UINT64":
    case "DATE":
    case "TIME":
    case "DATETIME":
    case "TIMESTAMP":
    case "BLOB":
    case "BIT":
    case "VARBINARY":
    case "BINARY":
    case "GEOMETRY":
      return value;
    case "JSON":
      return JSON.parse(decode(value));
    default:
      return decode(value);
  }
}

class DatabaseError extends Error {
  constructor(message, status, body2) {
    super(message);
    this.status = status;
    this.name = "DatabaseError";
    this.body = body2;
  }
}

class Client {
  constructor(config) {
    this.config = config;
  }
  async transaction(fn) {
    return this.connection().transaction(fn);
  }
  async execute(query, args = null, options = { as: "object" }) {
    return this.connection().execute(query, args, options);
  }
  connection() {
    return new Connection(this.config);
  }
}

class Tx {
  constructor(conn) {
    this.conn = conn;
  }
  async execute(query, args = null, options = { as: "object" }) {
    return this.conn.execute(query, args, options);
  }
}

class Connection {
  constructor(config) {
    var _a;
    this.session = null;
    this.config = { ...config };
    if (typeof fetch !== "undefined") {
      (_a = this.config).fetch || (_a.fetch = fetch);
    }
    if (config.url) {
      const url7 = new URL(config.url);
      this.config.username = url7.username;
      this.config.password = url7.password;
      this.config.host = url7.hostname;
      this.url = buildURL(url7);
    } else {
      this.url = new URL(`https://${this.config.host}`).toString();
    }
  }
  async transaction(fn) {
    const conn = new Connection(this.config);
    const tx = new Tx(conn);
    try {
      await tx.execute("BEGIN");
      const res = await fn(tx);
      await tx.execute("COMMIT");
      return res;
    } catch (err) {
      await tx.execute("ROLLBACK");
      throw err;
    }
  }
  async refresh() {
    await this.createSession();
  }
  async execute(query, args = null, options = { as: "object" }) {
    const url7 = new URL("/psdb.v1alpha1.Database/Execute", this.url);
    const formatter = this.config.format || format;
    const sql = args ? formatter(query, args) : query;
    const saved = await postJSON(this.config, url7, { query: sql, session: this.session });
    const { result, session, error, timing } = saved;
    if (session) {
      this.session = session;
    }
    if (error) {
      throw new DatabaseError(error.message, 400, error);
    }
    const rowsAffected = result?.rowsAffected ? parseInt(result.rowsAffected, 10) : 0;
    const insertId = result?.insertId ?? "0";
    const fields = result?.fields ?? [];
    for (const field of fields) {
      field.type || (field.type = "NULL");
    }
    const castFn = options.cast || this.config.cast || cast;
    const rows = result ? parse2(result, castFn, options.as || "object") : [];
    const headers = fields.map((f) => f.name);
    const typeByName = (acc, { name, type }) => ({ ...acc, [name]: type });
    const types = fields.reduce(typeByName, {});
    const timingSeconds = timing ?? 0;
    return {
      headers,
      types,
      fields,
      rows,
      rowsAffected,
      insertId,
      size: rows.length,
      statement: sql,
      time: timingSeconds * 1000
    };
  }
  async createSession() {
    const url7 = new URL("/psdb.v1alpha1.Database/CreateSession", this.url);
    const { session } = await postJSON(this.config, url7);
    this.session = session;
    return session;
  }
}

// node_modules/drizzle-orm/entity.js
var is = function(value, type) {
  if (!value || typeof value !== "object") {
    return false;
  }
  if (value instanceof type) {
    return true;
  }
  if (!Object.prototype.hasOwnProperty.call(type, entityKind)) {
    throw new Error(`Class "${type.name ?? "<unknown>"}" doesn't look like a Drizzle entity. If this is incorrect and the class is provided by Drizzle, please report this as a bug.`);
  }
  let cls = value.constructor;
  if (cls) {
    while (cls) {
      if (entityKind in cls && cls[entityKind] === type[entityKind]) {
        return true;
      }
      cls = Object.getPrototypeOf(cls);
    }
  }
  return false;
};
var entityKind = Symbol.for("drizzle:entityKind");
var hasOwnEntityKind = Symbol.for("drizzle:hasOwnEntityKind");

// node_modules/drizzle-orm/logger.js
class ConsoleLogWriter {
  static [entityKind] = "ConsoleLogWriter";
  write(message) {
    console.log(message);
  }
}

class DefaultLogger {
  static [entityKind] = "DefaultLogger";
  writer;
  constructor(config) {
    this.writer = config?.writer ?? new ConsoleLogWriter;
  }
  logQuery(query, params) {
    const stringifiedParams = params.map((p) => {
      try {
        return JSON.stringify(p);
      } catch {
        return String(p);
      }
    });
    const paramsStr = stringifiedParams.length ? ` -- params: [${stringifiedParams.join(", ")}]` : "";
    this.writer.write(`Query: ${query}${paramsStr}`);
  }
}

class NoopLogger {
  static [entityKind] = "NoopLogger";
  logQuery() {
  }
}

// node_modules/drizzle-orm/column.js
class Column {
  constructor(table, config) {
    this.table = table;
    this.config = config;
    this.name = config.name;
    this.notNull = config.notNull;
    this.default = config.default;
    this.defaultFn = config.defaultFn;
    this.hasDefault = config.hasDefault;
    this.primary = config.primaryKey;
    this.isUnique = config.isUnique;
    this.uniqueName = config.uniqueName;
    this.uniqueType = config.uniqueType;
    this.dataType = config.dataType;
    this.columnType = config.columnType;
  }
  static [entityKind] = "Column";
  name;
  primary;
  notNull;
  default;
  defaultFn;
  hasDefault;
  isUnique;
  uniqueName;
  uniqueType;
  dataType;
  columnType;
  enumValues = undefined;
  config;
  mapFromDriverValue(value) {
    return value;
  }
  mapToDriverValue(value) {
    return value;
  }
}

// node_modules/drizzle-orm/table.js
var isTable = function(table) {
  return typeof table === "object" && table !== null && IsDrizzleTable in table;
};
var getTableName = function(table) {
  return table[TableName];
};
var TableName = Symbol.for("drizzle:Name");
var Schema = Symbol.for("drizzle:Schema");
var Columns = Symbol.for("drizzle:Columns");
var OriginalName = Symbol.for("drizzle:OriginalName");
var BaseName = Symbol.for("drizzle:BaseName");
var IsAlias = Symbol.for("drizzle:IsAlias");
var ExtraConfigBuilder = Symbol.for("drizzle:ExtraConfigBuilder");
var IsDrizzleTable = Symbol.for("drizzle:IsDrizzleTable");

class Table {
  static [entityKind] = "Table";
  static Symbol = {
    Name: TableName,
    Schema,
    OriginalName,
    Columns,
    BaseName,
    IsAlias,
    ExtraConfigBuilder
  };
  [TableName];
  [OriginalName];
  [Schema];
  [Columns];
  [BaseName];
  [IsAlias] = false;
  [ExtraConfigBuilder] = undefined;
  [IsDrizzleTable] = true;
  constructor(name, schema, baseName) {
    this[TableName] = this[OriginalName] = name;
    this[Schema] = schema;
    this[BaseName] = baseName;
  }
}

// node_modules/drizzle-orm/pg-core/table.js
var InlineForeignKeys = Symbol.for("drizzle:PgInlineForeignKeys");

class PgTable extends Table {
  static [entityKind] = "PgTable";
  static Symbol = Object.assign({}, Table.Symbol, {
    InlineForeignKeys
  });
  [InlineForeignKeys] = [];
  [Table.Symbol.ExtraConfigBuilder] = undefined;
}

// node_modules/drizzle-orm/pg-core/primary-keys.js
class PrimaryKeyBuilder {
  static [entityKind] = "PgPrimaryKeyBuilder";
  columns;
  name;
  constructor(columns, name) {
    this.columns = columns;
    this.name = name;
  }
  build(table3) {
    return new PrimaryKey(table3, this.columns, this.name);
  }
}

class PrimaryKey {
  constructor(table3, columns, name) {
    this.table = table3;
    this.columns = columns;
    this.name = name;
  }
  static [entityKind] = "PgPrimaryKey";
  columns;
  name;
  getName() {
    return this.name ?? `${this.table[PgTable.Symbol.Name]}_${this.columns.map((column) => column.name).join("_")}_pk`;
  }
}

// node_modules/drizzle-orm/sql/expressions/conditions.js
var bindIfParam = function(value, column2) {
  if (isDriverValueEncoder(column2) && !isSQLWrapper(value) && !is(value, Param) && !is(value, Placeholder) && !is(value, Column) && !is(value, Table) && !is(value, View)) {
    return new Param(value, column2);
  }
  return value;
};
var and = function(...unfilteredConditions) {
  const conditions = unfilteredConditions.filter((c) => c !== undefined);
  if (conditions.length === 0) {
    return;
  }
  if (conditions.length === 1) {
    return new SQL(conditions);
  }
  return new SQL([
    new StringChunk("("),
    sql2.join(conditions, new StringChunk(" and ")),
    new StringChunk(")")
  ]);
};
var or = function(...unfilteredConditions) {
  const conditions = unfilteredConditions.filter((c) => c !== undefined);
  if (conditions.length === 0) {
    return;
  }
  if (conditions.length === 1) {
    return new SQL(conditions);
  }
  return new SQL([
    new StringChunk("("),
    sql2.join(conditions, new StringChunk(" or ")),
    new StringChunk(")")
  ]);
};
var not = function(condition) {
  return sql2`not ${condition}`;
};
var inArray = function(column2, values) {
  if (Array.isArray(values)) {
    if (values.length === 0) {
      throw new Error("inArray requires at least one value");
    }
    return sql2`${column2} in ${values.map((v) => bindIfParam(v, column2))}`;
  }
  return sql2`${column2} in ${bindIfParam(values, column2)}`;
};
var notInArray = function(column2, values) {
  if (Array.isArray(values)) {
    if (values.length === 0) {
      throw new Error("notInArray requires at least one value");
    }
    return sql2`${column2} not in ${values.map((v) => bindIfParam(v, column2))}`;
  }
  return sql2`${column2} not in ${bindIfParam(values, column2)}`;
};
var isNull = function(value) {
  return sql2`${value} is null`;
};
var isNotNull = function(value) {
  return sql2`${value} is not null`;
};
var exists = function(subquery) {
  return sql2`exists ${subquery}`;
};
var notExists = function(subquery) {
  return sql2`not exists ${subquery}`;
};
var between = function(column2, min, max) {
  return sql2`${column2} between ${bindIfParam(min, column2)} and ${bindIfParam(max, column2)}`;
};
var notBetween = function(column2, min, max) {
  return sql2`${column2} not between ${bindIfParam(min, column2)} and ${bindIfParam(max, column2)}`;
};
var like = function(column2, value) {
  return sql2`${column2} like ${value}`;
};
var notLike = function(column2, value) {
  return sql2`${column2} not like ${value}`;
};
var ilike = function(column2, value) {
  return sql2`${column2} ilike ${value}`;
};
var notIlike = function(column2, value) {
  return sql2`${column2} not ilike ${value}`;
};
var eq = (left, right) => {
  return sql2`${left} = ${bindIfParam(right, left)}`;
};
var ne = (left, right) => {
  return sql2`${left} <> ${bindIfParam(right, left)}`;
};
var gt = (left, right) => {
  return sql2`${left} > ${bindIfParam(right, left)}`;
};
var gte = (left, right) => {
  return sql2`${left} >= ${bindIfParam(right, left)}`;
};
var lt = (left, right) => {
  return sql2`${left} < ${bindIfParam(right, left)}`;
};
var lte = (left, right) => {
  return sql2`${left} <= ${bindIfParam(right, left)}`;
};

// node_modules/drizzle-orm/sql/expressions/select.js
var asc = function(column2) {
  return sql2`${column2} asc`;
};
var desc = function(column2) {
  return sql2`${column2} desc`;
};

// node_modules/drizzle-orm/relations.js
var getOperators = function() {
  return {
    and,
    between,
    eq,
    exists,
    gt,
    gte,
    ilike,
    inArray,
    isNull,
    isNotNull,
    like,
    lt,
    lte,
    ne,
    not,
    notBetween,
    notExists,
    notLike,
    notIlike,
    notInArray,
    or,
    sql: sql2
  };
};
var getOrderByOperators = function() {
  return {
    sql: sql2,
    asc,
    desc
  };
};
var extractTablesRelationalConfig = function(schema, configHelpers) {
  if (Object.keys(schema).length === 1 && "default" in schema && !is(schema["default"], Table)) {
    schema = schema["default"];
  }
  const tableNamesMap = {};
  const relationsBuffer = {};
  const tablesConfig = {};
  for (const [key, value] of Object.entries(schema)) {
    if (isTable(value)) {
      const dbName = value[Table.Symbol.Name];
      const bufferedRelations = relationsBuffer[dbName];
      tableNamesMap[dbName] = key;
      tablesConfig[key] = {
        tsName: key,
        dbName: value[Table.Symbol.Name],
        schema: value[Table.Symbol.Schema],
        columns: value[Table.Symbol.Columns],
        relations: bufferedRelations?.relations ?? {},
        primaryKey: bufferedRelations?.primaryKey ?? []
      };
      for (const column3 of Object.values(value[Table.Symbol.Columns])) {
        if (column3.primary) {
          tablesConfig[key].primaryKey.push(column3);
        }
      }
      const extraConfig = value[Table.Symbol.ExtraConfigBuilder]?.(value);
      if (extraConfig) {
        for (const configEntry of Object.values(extraConfig)) {
          if (is(configEntry, PrimaryKeyBuilder)) {
            tablesConfig[key].primaryKey.push(...configEntry.columns);
          }
        }
      }
    } else if (is(value, Relations)) {
      const dbName = value.table[Table.Symbol.Name];
      const tableName = tableNamesMap[dbName];
      const relations2 = value.config(configHelpers(value.table));
      let primaryKey;
      for (const [relationName, relation] of Object.entries(relations2)) {
        if (tableName) {
          const tableConfig = tablesConfig[tableName];
          tableConfig.relations[relationName] = relation;
          if (primaryKey) {
            tableConfig.primaryKey.push(...primaryKey);
          }
        } else {
          if (!(dbName in relationsBuffer)) {
            relationsBuffer[dbName] = {
              relations: {},
              primaryKey
            };
          }
          relationsBuffer[dbName].relations[relationName] = relation;
        }
      }
    }
  }
  return { tables: tablesConfig, tableNamesMap };
};
var createOne = function(sourceTable) {
  return function one(table5, config) {
    return new One(sourceTable, table5, config, config?.fields.reduce((res, f) => res && f.notNull, true) ?? false);
  };
};
var createMany = function(sourceTable) {
  return function many(referencedTable, config) {
    return new Many(sourceTable, referencedTable, config);
  };
};
var normalizeRelation = function(schema, tableNamesMap, relation) {
  if (is(relation, One) && relation.config) {
    return {
      fields: relation.config.fields,
      references: relation.config.references
    };
  }
  const referencedTableTsName = tableNamesMap[relation.referencedTable[Table.Symbol.Name]];
  if (!referencedTableTsName) {
    throw new Error(`Table "${relation.referencedTable[Table.Symbol.Name]}" not found in schema`);
  }
  const referencedTableConfig = schema[referencedTableTsName];
  if (!referencedTableConfig) {
    throw new Error(`Table "${referencedTableTsName}" not found in schema`);
  }
  const sourceTable = relation.sourceTable;
  const sourceTableTsName = tableNamesMap[sourceTable[Table.Symbol.Name]];
  if (!sourceTableTsName) {
    throw new Error(`Table "${sourceTable[Table.Symbol.Name]}" not found in schema`);
  }
  const reverseRelations = [];
  for (const referencedTableRelation of Object.values(referencedTableConfig.relations)) {
    if (relation.relationName && relation !== referencedTableRelation && referencedTableRelation.relationName === relation.relationName || !relation.relationName && referencedTableRelation.referencedTable === relation.sourceTable) {
      reverseRelations.push(referencedTableRelation);
    }
  }
  if (reverseRelations.length > 1) {
    throw relation.relationName ? new Error(`There are multiple relations with name "${relation.relationName}" in table "${referencedTableTsName}"`) : new Error(`There are multiple relations between "${referencedTableTsName}" and "${relation.sourceTable[Table.Symbol.Name]}". Please specify relation name`);
  }
  if (reverseRelations[0] && is(reverseRelations[0], One) && reverseRelations[0].config) {
    return {
      fields: reverseRelations[0].config.references,
      references: reverseRelations[0].config.fields
    };
  }
  throw new Error(`There is not enough information to infer relation "${sourceTableTsName}.${relation.fieldName}"`);
};
var createTableRelationsHelpers = function(sourceTable) {
  return {
    one: createOne(sourceTable),
    many: createMany(sourceTable)
  };
};
var mapRelationalRow = function(tablesConfig, tableConfig, row, buildQueryResultSelection, mapColumnValue = (value) => value) {
  const result = {};
  for (const [
    selectionItemIndex,
    selectionItem
  ] of buildQueryResultSelection.entries()) {
    if (selectionItem.isJson) {
      const relation = tableConfig.relations[selectionItem.tsKey];
      const rawSubRows = row[selectionItemIndex];
      const subRows = typeof rawSubRows === "string" ? JSON.parse(rawSubRows) : rawSubRows;
      result[selectionItem.tsKey] = is(relation, One) ? subRows && mapRelationalRow(tablesConfig, tablesConfig[selectionItem.relationTableTsKey], subRows, selectionItem.selection, mapColumnValue) : subRows.map((subRow) => mapRelationalRow(tablesConfig, tablesConfig[selectionItem.relationTableTsKey], subRow, selectionItem.selection, mapColumnValue));
    } else {
      const value = mapColumnValue(row[selectionItemIndex]);
      const field = selectionItem.field;
      let decoder2;
      if (is(field, Column)) {
        decoder2 = field;
      } else if (is(field, SQL)) {
        decoder2 = field.decoder;
      } else {
        decoder2 = field.sql.decoder;
      }
      result[selectionItem.tsKey] = value === null ? null : decoder2.mapFromDriverValue(value);
    }
  }
  return result;
};

class Relation {
  constructor(sourceTable, referencedTable, relationName) {
    this.sourceTable = sourceTable;
    this.referencedTable = referencedTable;
    this.relationName = relationName;
    this.referencedTableName = referencedTable[Table.Symbol.Name];
  }
  static [entityKind] = "Relation";
  referencedTableName;
  fieldName;
}

class Relations {
  constructor(table5, config) {
    this.table = table5;
    this.config = config;
  }
  static [entityKind] = "Relations";
}

class One extends Relation {
  constructor(sourceTable, referencedTable, config, isNullable) {
    super(sourceTable, referencedTable, config?.relationName);
    this.config = config;
    this.isNullable = isNullable;
  }
  static [entityKind] = "One";
  withFieldName(fieldName) {
    const relation = new One(this.sourceTable, this.referencedTable, this.config, this.isNullable);
    relation.fieldName = fieldName;
    return relation;
  }
}

class Many extends Relation {
  constructor(sourceTable, referencedTable, config) {
    super(sourceTable, referencedTable, config?.relationName);
    this.config = config;
  }
  static [entityKind] = "Many";
  withFieldName(fieldName) {
    const relation = new Many(this.sourceTable, this.referencedTable, this.config);
    relation.fieldName = fieldName;
    return relation;
  }
}

// node_modules/drizzle-orm/subquery.js
var SubqueryConfig = Symbol.for("drizzle:SubqueryConfig");

class Subquery {
  static [entityKind] = "Subquery";
  [SubqueryConfig];
  constructor(sql5, selection, alias, isWith = false) {
    this[SubqueryConfig] = {
      sql: sql5,
      selection,
      alias,
      isWith
    };
  }
}

class WithSubquery extends Subquery {
  static [entityKind] = "WithSubquery";
}

// node_modules/drizzle-orm/tracing-utils.js
var iife = function(fn, ...args) {
  return fn(...args);
};

// node_modules/drizzle-orm/version.js
var version2 = "0.29.3";

// node_modules/drizzle-orm/tracing.js
var otel;
var rawTracer;
var tracer = {
  startActiveSpan(name, fn) {
    if (!otel) {
      return fn();
    }
    if (!rawTracer) {
      rawTracer = otel.trace.getTracer("drizzle-orm", version2);
    }
    return iife((otel2, rawTracer2) => rawTracer2.startActiveSpan(name, (span) => {
      try {
        return fn(span);
      } catch (e) {
        span.setStatus({
          code: otel2.SpanStatusCode.ERROR,
          message: e instanceof Error ? e.message : "Unknown error"
        });
        throw e;
      } finally {
        span.end();
      }
    }), otel, rawTracer);
  }
};

// node_modules/drizzle-orm/view-common.js
var ViewBaseConfig = Symbol.for("drizzle:ViewBaseConfig");

// node_modules/drizzle-orm/sql/sql.js
var isSQLWrapper = function(value) {
  return typeof value === "object" && value !== null && "getSQL" in value && typeof value.getSQL === "function";
};
var mergeQueries = function(queries) {
  const result = { sql: "", params: [] };
  for (const query of queries) {
    result.sql += query.sql;
    result.params.push(...query.params);
    if (query.typings?.length) {
      if (!result.typings) {
        result.typings = [];
      }
      result.typings.push(...query.typings);
    }
  }
  return result;
};
var isDriverValueEncoder = function(value) {
  return typeof value === "object" && value !== null && "mapToDriverValue" in value && typeof value.mapToDriverValue === "function";
};
var sql2 = function(strings, ...params) {
  const queryChunks = [];
  if (params.length > 0 || strings.length > 0 && strings[0] !== "") {
    queryChunks.push(new StringChunk(strings[0]));
  }
  for (const [paramIndex, param2] of params.entries()) {
    queryChunks.push(param2, new StringChunk(strings[paramIndex + 1]));
  }
  return new SQL(queryChunks);
};
var fillPlaceholders = function(params, values) {
  return params.map((p) => {
    if (is(p, Placeholder)) {
      if (!(p.name in values)) {
        throw new Error(`No value for placeholder "${p.name}" was provided`);
      }
      return values[p.name];
    }
    return p;
  });
};
class StringChunk {
  static [entityKind] = "StringChunk";
  value;
  constructor(value) {
    this.value = Array.isArray(value) ? value : [value];
  }
  getSQL() {
    return new SQL([this]);
  }
}

class SQL {
  constructor(queryChunks) {
    this.queryChunks = queryChunks;
  }
  static [entityKind] = "SQL";
  decoder = noopDecoder;
  shouldInlineParams = false;
  append(query) {
    this.queryChunks.push(...query.queryChunks);
    return this;
  }
  toQuery(config) {
    return tracer.startActiveSpan("drizzle.buildSQL", (span) => {
      const query = this.buildQueryFromSourceParams(this.queryChunks, config);
      span?.setAttributes({
        "drizzle.query.text": query.sql,
        "drizzle.query.params": JSON.stringify(query.params)
      });
      return query;
    });
  }
  buildQueryFromSourceParams(chunks, _config) {
    const config = Object.assign({}, _config, {
      inlineParams: _config.inlineParams || this.shouldInlineParams,
      paramStartIndex: _config.paramStartIndex || { value: 0 }
    });
    const {
      escapeName,
      escapeParam,
      prepareTyping,
      inlineParams,
      paramStartIndex
    } = config;
    return mergeQueries(chunks.map((chunk) => {
      if (is(chunk, StringChunk)) {
        return { sql: chunk.value.join(""), params: [] };
      }
      if (is(chunk, Name)) {
        return { sql: escapeName(chunk.value), params: [] };
      }
      if (chunk === undefined) {
        return { sql: "", params: [] };
      }
      if (Array.isArray(chunk)) {
        const result = [new StringChunk("(")];
        for (const [i, p] of chunk.entries()) {
          result.push(p);
          if (i < chunk.length - 1) {
            result.push(new StringChunk(", "));
          }
        }
        result.push(new StringChunk(")"));
        return this.buildQueryFromSourceParams(result, config);
      }
      if (is(chunk, SQL)) {
        return this.buildQueryFromSourceParams(chunk.queryChunks, {
          ...config,
          inlineParams: inlineParams || chunk.shouldInlineParams
        });
      }
      if (is(chunk, Table)) {
        const schemaName = chunk[Table.Symbol.Schema];
        const tableName = chunk[Table.Symbol.Name];
        return {
          sql: schemaName === undefined ? escapeName(tableName) : escapeName(schemaName) + "." + escapeName(tableName),
          params: []
        };
      }
      if (is(chunk, Column)) {
        return { sql: escapeName(chunk.table[Table.Symbol.Name]) + "." + escapeName(chunk.name), params: [] };
      }
      if (is(chunk, View)) {
        const schemaName = chunk[ViewBaseConfig].schema;
        const viewName = chunk[ViewBaseConfig].name;
        return {
          sql: schemaName === undefined ? escapeName(viewName) : escapeName(schemaName) + "." + escapeName(viewName),
          params: []
        };
      }
      if (is(chunk, Param)) {
        const mappedValue = chunk.value === null ? null : chunk.encoder.mapToDriverValue(chunk.value);
        if (is(mappedValue, SQL)) {
          return this.buildQueryFromSourceParams([mappedValue], config);
        }
        if (inlineParams) {
          return { sql: this.mapInlineParam(mappedValue, config), params: [] };
        }
        let typings;
        if (prepareTyping !== undefined) {
          typings = [prepareTyping(chunk.encoder)];
        }
        return { sql: escapeParam(paramStartIndex.value++, mappedValue), params: [mappedValue], typings };
      }
      if (is(chunk, Placeholder)) {
        return { sql: escapeParam(paramStartIndex.value++, chunk), params: [chunk] };
      }
      if (is(chunk, SQL.Aliased) && chunk.fieldAlias !== undefined) {
        return { sql: escapeName(chunk.fieldAlias), params: [] };
      }
      if (is(chunk, Subquery)) {
        if (chunk[SubqueryConfig].isWith) {
          return { sql: escapeName(chunk[SubqueryConfig].alias), params: [] };
        }
        return this.buildQueryFromSourceParams([
          new StringChunk("("),
          chunk[SubqueryConfig].sql,
          new StringChunk(") "),
          new Name(chunk[SubqueryConfig].alias)
        ], config);
      }
      if (isSQLWrapper(chunk)) {
        return this.buildQueryFromSourceParams([
          new StringChunk("("),
          chunk.getSQL(),
          new StringChunk(")")
        ], config);
      }
      if (is(chunk, Relation)) {
        return this.buildQueryFromSourceParams([
          chunk.sourceTable,
          new StringChunk("."),
          sql2.identifier(chunk.fieldName)
        ], config);
      }
      if (inlineParams) {
        return { sql: this.mapInlineParam(chunk, config), params: [] };
      }
      return { sql: escapeParam(paramStartIndex.value++, chunk), params: [chunk] };
    }));
  }
  mapInlineParam(chunk, { escapeString }) {
    if (chunk === null) {
      return "null";
    }
    if (typeof chunk === "number" || typeof chunk === "boolean") {
      return chunk.toString();
    }
    if (typeof chunk === "string") {
      return escapeString(chunk);
    }
    if (typeof chunk === "object") {
      const mappedValueAsString = chunk.toString();
      if (mappedValueAsString === "[object Object]") {
        return escapeString(JSON.stringify(chunk));
      }
      return escapeString(mappedValueAsString);
    }
    throw new Error("Unexpected param value: " + chunk);
  }
  getSQL() {
    return this;
  }
  as(alias) {
    if (alias === undefined) {
      return this;
    }
    return new SQL.Aliased(this, alias);
  }
  mapWith(decoder2) {
    this.decoder = typeof decoder2 === "function" ? { mapFromDriverValue: decoder2 } : decoder2;
    return this;
  }
  inlineParams() {
    this.shouldInlineParams = true;
    return this;
  }
}

class Name {
  constructor(value) {
    this.value = value;
  }
  static [entityKind] = "Name";
  brand;
  getSQL() {
    return new SQL([this]);
  }
}
var noopDecoder = {
  mapFromDriverValue: (value) => value
};
var noopEncoder = {
  mapToDriverValue: (value) => value
};
var noopMapper = {
  ...noopDecoder,
  ...noopEncoder
};

class Param {
  constructor(value, encoder = noopEncoder) {
    this.value = value;
    this.encoder = encoder;
  }
  static [entityKind] = "Param";
  brand;
  getSQL() {
    return new SQL([this]);
  }
}
((sql22) => {
  function empty() {
    return new SQL([]);
  }
  sql22.empty = empty;
  function fromList(list) {
    return new SQL(list);
  }
  sql22.fromList = fromList;
  function raw2(str) {
    return new SQL([new StringChunk(str)]);
  }
  sql22.raw = raw2;
  function join(chunks, separator) {
    const result = [];
    for (const [i, chunk] of chunks.entries()) {
      if (i > 0 && separator !== undefined) {
        result.push(separator);
      }
      result.push(chunk);
    }
    return new SQL(result);
  }
  sql22.join = join;
  function identifier(value) {
    return new Name(value);
  }
  sql22.identifier = identifier;
  function placeholder2(name2) {
    return new Placeholder(name2);
  }
  sql22.placeholder = placeholder2;
  function param2(value, encoder) {
    return new Param(value, encoder);
  }
  sql22.param = param2;
})(sql2 || (sql2 = {}));
((SQL2) => {

  class Aliased {
    constructor(sql22, fieldAlias) {
      this.sql = sql22;
      this.fieldAlias = fieldAlias;
    }
    static [entityKind] = "SQL.Aliased";
    isSelectionField = false;
    getSQL() {
      return this.sql;
    }
    clone() {
      return new Aliased(this.sql, this.fieldAlias);
    }
  }
  SQL2.Aliased = Aliased;
})(SQL || (SQL = {}));

class Placeholder {
  constructor(name2) {
    this.name = name2;
  }
  static [entityKind] = "Placeholder";
  getSQL() {
    return new SQL([this]);
  }
}

class View {
  static [entityKind] = "View";
  [ViewBaseConfig];
  constructor({ name: name2, schema, selectedFields, query }) {
    this[ViewBaseConfig] = {
      name: name2,
      originalName: name2,
      schema,
      selectedFields,
      query,
      isExisting: !query,
      isAlias: false
    };
  }
  getSQL() {
    return new SQL([this]);
  }
}
Column.prototype.getSQL = function() {
  return new SQL([this]);
};
Table.prototype.getSQL = function() {
  return new SQL([this]);
};
Subquery.prototype.getSQL = function() {
  return new SQL([this]);
};

// node_modules/drizzle-orm/alias.js
var aliasedTable = function(table7, tableAlias) {
  return new Proxy(table7, new TableAliasProxyHandler(tableAlias, false));
};
var aliasedTableColumn = function(column5, tableAlias) {
  return new Proxy(column5, new ColumnAliasProxyHandler(new Proxy(column5.table, new TableAliasProxyHandler(tableAlias, false))));
};
var mapColumnsInAliasedSQLToAlias = function(query, alias) {
  return new SQL.Aliased(mapColumnsInSQLToAlias(query.sql, alias), query.fieldAlias);
};
var mapColumnsInSQLToAlias = function(query, alias) {
  return sql2.join(query.queryChunks.map((c) => {
    if (is(c, Column)) {
      return aliasedTableColumn(c, alias);
    }
    if (is(c, SQL)) {
      return mapColumnsInSQLToAlias(c, alias);
    }
    if (is(c, SQL.Aliased)) {
      return mapColumnsInAliasedSQLToAlias(c, alias);
    }
    return c;
  }));
};

class ColumnAliasProxyHandler {
  constructor(table7) {
    this.table = table7;
  }
  static [entityKind] = "ColumnAliasProxyHandler";
  get(columnObj, prop) {
    if (prop === "table") {
      return this.table;
    }
    return columnObj[prop];
  }
}

class TableAliasProxyHandler {
  constructor(alias, replaceOriginalName) {
    this.alias = alias;
    this.replaceOriginalName = replaceOriginalName;
  }
  static [entityKind] = "TableAliasProxyHandler";
  get(target, prop) {
    if (prop === Table.Symbol.IsAlias) {
      return true;
    }
    if (prop === Table.Symbol.Name) {
      return this.alias;
    }
    if (this.replaceOriginalName && prop === Table.Symbol.OriginalName) {
      return this.alias;
    }
    if (prop === ViewBaseConfig) {
      return {
        ...target[ViewBaseConfig],
        name: this.alias,
        isAlias: true
      };
    }
    if (prop === Table.Symbol.Columns) {
      const columns = target[Table.Symbol.Columns];
      if (!columns) {
        return columns;
      }
      const proxiedColumns = {};
      Object.keys(columns).map((key) => {
        proxiedColumns[key] = new Proxy(columns[key], new ColumnAliasProxyHandler(new Proxy(target, this)));
      });
      return proxiedColumns;
    }
    const value = target[prop];
    if (is(value, Column)) {
      return new Proxy(value, new ColumnAliasProxyHandler(new Proxy(target, this)));
    }
    return value;
  }
}

// node_modules/drizzle-orm/selection-proxy.js
class SelectionProxyHandler {
  static [entityKind] = "SelectionProxyHandler";
  config;
  constructor(config) {
    this.config = { ...config };
  }
  get(subquery3, prop) {
    if (prop === SubqueryConfig) {
      return {
        ...subquery3[SubqueryConfig],
        selection: new Proxy(subquery3[SubqueryConfig].selection, this)
      };
    }
    if (prop === ViewBaseConfig) {
      return {
        ...subquery3[ViewBaseConfig],
        selectedFields: new Proxy(subquery3[ViewBaseConfig].selectedFields, this)
      };
    }
    if (typeof prop === "symbol") {
      return subquery3[prop];
    }
    const columns = is(subquery3, Subquery) ? subquery3[SubqueryConfig].selection : is(subquery3, View) ? subquery3[ViewBaseConfig].selectedFields : subquery3;
    const value = columns[prop];
    if (is(value, SQL.Aliased)) {
      if (this.config.sqlAliasedBehavior === "sql" && !value.isSelectionField) {
        return value.sql;
      }
      const newValue = value.clone();
      newValue.isSelectionField = true;
      return newValue;
    }
    if (is(value, SQL)) {
      if (this.config.sqlBehavior === "sql") {
        return value;
      }
      throw new Error(`You tried to reference "${prop}" field from a subquery, which is a raw SQL field, but it doesn't have an alias declared. Please add an alias to the field using ".as('alias')" method.`);
    }
    if (is(value, Column)) {
      if (this.config.alias) {
        return new Proxy(value, new ColumnAliasProxyHandler(new Proxy(value.table, new TableAliasProxyHandler(this.config.alias, this.config.replaceOriginalName ?? false))));
      }
      return value;
    }
    if (typeof value !== "object" || value === null) {
      return value;
    }
    return new Proxy(value, new SelectionProxyHandler(this.config));
  }
}

// node_modules/drizzle-orm/query-promise.js
class QueryPromise {
  static [entityKind] = "QueryPromise";
  [Symbol.toStringTag] = "QueryPromise";
  catch(onRejected) {
    return this.then(undefined, onRejected);
  }
  finally(onFinally) {
    return this.then((value) => {
      onFinally?.();
      return value;
    }, (reason) => {
      onFinally?.();
      throw reason;
    });
  }
  then(onFulfilled, onRejected) {
    return this.execute().then(onFulfilled, onRejected);
  }
}

// node_modules/drizzle-orm/mysql-core/query-builders/delete.js
class MySqlDeleteBase extends QueryPromise {
  constructor(table7, session, dialect) {
    super();
    this.table = table7;
    this.session = session;
    this.dialect = dialect;
    this.config = { table: table7 };
  }
  static [entityKind] = "MySqlDelete";
  config;
  where(where) {
    this.config.where = where;
    return this;
  }
  getSQL() {
    return this.dialect.buildDeleteQuery(this.config);
  }
  toSQL() {
    const { typings: _typings, ...rest } = this.dialect.sqlToQuery(this.getSQL());
    return rest;
  }
  prepare() {
    return this.session.prepareQuery(this.dialect.sqlToQuery(this.getSQL()), this.config.returning);
  }
  execute = (placeholderValues) => {
    return this.prepare().execute(placeholderValues);
  };
  createIterator = () => {
    const self = this;
    return async function* (placeholderValues) {
      yield* self.prepare().iterator(placeholderValues);
    };
  };
  iterator = this.createIterator();
  $dynamic() {
    return this;
  }
}

// node_modules/drizzle-orm/utils.js
var mapResultRow = function(columns, row, joinsNotNullableMap) {
  const nullifyMap = {};
  const result = columns.reduce((result2, { path, field }, columnIndex) => {
    let decoder2;
    if (is(field, Column)) {
      decoder2 = field;
    } else if (is(field, SQL)) {
      decoder2 = field.decoder;
    } else {
      decoder2 = field.sql.decoder;
    }
    let node4 = result2;
    for (const [pathChunkIndex, pathChunk] of path.entries()) {
      if (pathChunkIndex < path.length - 1) {
        if (!(pathChunk in node4)) {
          node4[pathChunk] = {};
        }
        node4 = node4[pathChunk];
      } else {
        const rawValue = row[columnIndex];
        const value = node4[pathChunk] = rawValue === null ? null : decoder2.mapFromDriverValue(rawValue);
        if (joinsNotNullableMap && is(field, Column) && path.length === 2) {
          const objectName = path[0];
          if (!(objectName in nullifyMap)) {
            nullifyMap[objectName] = value === null ? getTableName(field.table) : false;
          } else if (typeof nullifyMap[objectName] === "string" && nullifyMap[objectName] !== getTableName(field.table)) {
            nullifyMap[objectName] = false;
          }
        }
      }
    }
    return result2;
  }, {});
  if (joinsNotNullableMap && Object.keys(nullifyMap).length > 0) {
    for (const [objectName, tableName] of Object.entries(nullifyMap)) {
      if (typeof tableName === "string" && !joinsNotNullableMap[tableName]) {
        result[objectName] = null;
      }
    }
  }
  return result;
};
var orderSelectedFields = function(fields, pathPrefix) {
  return Object.entries(fields).reduce((result, [name, field]) => {
    if (typeof name !== "string") {
      return result;
    }
    const newPath = pathPrefix ? [...pathPrefix, name] : [name];
    if (is(field, Column) || is(field, SQL) || is(field, SQL.Aliased)) {
      result.push({ path: newPath, field });
    } else if (is(field, Table)) {
      result.push(...orderSelectedFields(field[Table.Symbol.Columns], newPath));
    } else {
      result.push(...orderSelectedFields(field, newPath));
    }
    return result;
  }, []);
};
var haveSameKeys = function(left, right) {
  const leftKeys = Object.keys(left);
  const rightKeys = Object.keys(right);
  if (leftKeys.length !== rightKeys.length) {
    return false;
  }
  for (const [index, key] of leftKeys.entries()) {
    if (key !== rightKeys[index]) {
      return false;
    }
  }
  return true;
};
var mapUpdateSet = function(table8, values) {
  const entries = Object.entries(values).filter(([, value]) => value !== undefined).map(([key, value]) => {
    if (is(value, SQL)) {
      return [key, value];
    } else {
      return [key, new Param(value, table8[Table.Symbol.Columns][key])];
    }
  });
  if (entries.length === 0) {
    throw new Error("No values to set");
  }
  return Object.fromEntries(entries);
};
var applyMixins = function(baseClass, extendedClasses) {
  for (const extendedClass of extendedClasses) {
    for (const name of Object.getOwnPropertyNames(extendedClass.prototype)) {
      if (name === "constructor")
        continue;
      Object.defineProperty(baseClass.prototype, name, Object.getOwnPropertyDescriptor(extendedClass.prototype, name) || Object.create(null));
    }
  }
};
var getTableColumns = function(table8) {
  return table8[Table.Symbol.Columns];
};
var getTableLikeName = function(table8) {
  return is(table8, Subquery) ? table8[SubqueryConfig].alias : is(table8, View) ? table8[ViewBaseConfig].name : is(table8, SQL) ? undefined : table8[Table.Symbol.IsAlias] ? table8[Table.Symbol.Name] : table8[Table.Symbol.BaseName];
};

// node_modules/drizzle-orm/mysql-core/query-builders/insert.js
class MySqlInsertBuilder {
  constructor(table9, session, dialect) {
    this.table = table9;
    this.session = session;
    this.dialect = dialect;
  }
  static [entityKind] = "MySqlInsertBuilder";
  shouldIgnore = false;
  ignore() {
    this.shouldIgnore = true;
    return this;
  }
  values(values) {
    values = Array.isArray(values) ? values : [values];
    if (values.length === 0) {
      throw new Error("values() must be called with at least one value");
    }
    const mappedValues = values.map((entry) => {
      const result = {};
      const cols = this.table[Table.Symbol.Columns];
      for (const colKey of Object.keys(entry)) {
        const colValue = entry[colKey];
        result[colKey] = is(colValue, SQL) ? colValue : new Param(colValue, cols[colKey]);
      }
      return result;
    });
    return new MySqlInsertBase(this.table, mappedValues, this.shouldIgnore, this.session, this.dialect);
  }
}

class MySqlInsertBase extends QueryPromise {
  constructor(table9, values, ignore, session, dialect) {
    super();
    this.session = session;
    this.dialect = dialect;
    this.config = { table: table9, values, ignore };
  }
  static [entityKind] = "MySqlInsert";
  config;
  onDuplicateKeyUpdate(config) {
    const setSql = this.dialect.buildUpdateSet(this.config.table, mapUpdateSet(this.config.table, config.set));
    this.config.onConflict = sql2`update ${setSql}`;
    return this;
  }
  getSQL() {
    return this.dialect.buildInsertQuery(this.config);
  }
  toSQL() {
    const { typings: _typings, ...rest } = this.dialect.sqlToQuery(this.getSQL());
    return rest;
  }
  prepare() {
    return this.session.prepareQuery(this.dialect.sqlToQuery(this.getSQL()), undefined);
  }
  execute = (placeholderValues) => {
    return this.prepare().execute(placeholderValues);
  };
  createIterator = () => {
    const self = this;
    return async function* (placeholderValues) {
      yield* self.prepare().iterator(placeholderValues);
    };
  };
  iterator = this.createIterator();
  $dynamic() {
    return this;
  }
}

// node_modules/drizzle-orm/column-builder.js
class ColumnBuilder {
  static [entityKind] = "ColumnBuilder";
  config;
  constructor(name, dataType, columnType) {
    this.config = {
      name,
      notNull: false,
      default: undefined,
      hasDefault: false,
      primaryKey: false,
      isUnique: false,
      uniqueName: undefined,
      uniqueType: undefined,
      dataType,
      columnType
    };
  }
  $type() {
    return this;
  }
  notNull() {
    this.config.notNull = true;
    return this;
  }
  default(value) {
    this.config.default = value;
    this.config.hasDefault = true;
    return this;
  }
  $defaultFn(fn) {
    this.config.defaultFn = fn;
    this.config.hasDefault = true;
    return this;
  }
  $default = this.$defaultFn;
  primaryKey() {
    this.config.primaryKey = true;
    this.config.notNull = true;
    return this;
  }
}

// node_modules/drizzle-orm/errors.js
class DrizzleError extends Error {
  static [entityKind] = "DrizzleError";
  constructor({ message, cause }) {
    super(message);
    this.name = "DrizzleError";
    this.cause = cause;
  }
}

class TransactionRollbackError extends DrizzleError {
  static [entityKind] = "TransactionRollbackError";
  constructor() {
    super({ message: "Rollback" });
  }
}

// node_modules/drizzle-orm/mysql-core/table.js
var mysqlTableWithSchema = function(name, columns, extraConfig, schema, baseName = name) {
  const rawTable = new MySqlTable(name, schema, baseName);
  const builtColumns = Object.fromEntries(Object.entries(columns).map(([name2, colBuilderBase]) => {
    const colBuilder = colBuilderBase;
    const column7 = colBuilder.build(rawTable);
    rawTable[InlineForeignKeys2].push(...colBuilder.buildForeignKeys(column7, rawTable));
    return [name2, column7];
  }));
  const table10 = Object.assign(rawTable, builtColumns);
  table10[Table.Symbol.Columns] = builtColumns;
  if (extraConfig) {
    table10[MySqlTable.Symbol.ExtraConfigBuilder] = extraConfig;
  }
  return table10;
};
var mysqlTableCreator = function(customizeTableName) {
  return (name, columns, extraConfig) => {
    return mysqlTableWithSchema(customizeTableName(name), columns, extraConfig, undefined, name);
  };
};
var InlineForeignKeys2 = Symbol.for("drizzle:MySqlInlineForeignKeys");

class MySqlTable extends Table {
  static [entityKind] = "MySqlTable";
  static Symbol = Object.assign({}, Table.Symbol, {
    InlineForeignKeys: InlineForeignKeys2
  });
  [Table.Symbol.Columns];
  [InlineForeignKeys2] = [];
  [Table.Symbol.ExtraConfigBuilder] = undefined;
}

// node_modules/drizzle-orm/mysql-core/foreign-keys.js
class ForeignKeyBuilder {
  static [entityKind] = "MySqlForeignKeyBuilder";
  reference;
  _onUpdate;
  _onDelete;
  constructor(config, actions) {
    this.reference = () => {
      const { name, columns, foreignColumns } = config();
      return { name, columns, foreignTable: foreignColumns[0].table, foreignColumns };
    };
    if (actions) {
      this._onUpdate = actions.onUpdate;
      this._onDelete = actions.onDelete;
    }
  }
  onUpdate(action) {
    this._onUpdate = action;
    return this;
  }
  onDelete(action) {
    this._onDelete = action;
    return this;
  }
  build(table11) {
    return new ForeignKey(table11, this);
  }
}

class ForeignKey {
  constructor(table11, builder) {
    this.table = table11;
    this.reference = builder.reference;
    this.onUpdate = builder._onUpdate;
    this.onDelete = builder._onDelete;
  }
  static [entityKind] = "MySqlForeignKey";
  reference;
  onUpdate;
  onDelete;
  getName() {
    const { name, columns, foreignColumns } = this.reference();
    const columnNames = columns.map((column7) => column7.name);
    const foreignColumnNames = foreignColumns.map((column7) => column7.name);
    const chunks = [
      this.table[MySqlTable.Symbol.Name],
      ...columnNames,
      foreignColumns[0].table[MySqlTable.Symbol.Name],
      ...foreignColumnNames
    ];
    return name ?? `${chunks.join("_")}_fk`;
  }
}

// node_modules/drizzle-orm/mysql-core/unique-constraint.js
var uniqueKeyName = function(table12, columns) {
  return `${table12[MySqlTable.Symbol.Name]}_${columns.join("_")}_unique`;
};

// node_modules/drizzle-orm/mysql-core/columns/common.js
class MySqlColumnBuilder extends ColumnBuilder {
  static [entityKind] = "MySqlColumnBuilder";
  foreignKeyConfigs = [];
  references(ref, actions = {}) {
    this.foreignKeyConfigs.push({ ref, actions });
    return this;
  }
  unique(name) {
    this.config.isUnique = true;
    this.config.uniqueName = name;
    return this;
  }
  buildForeignKeys(column8, table12) {
    return this.foreignKeyConfigs.map(({ ref, actions }) => {
      return ((ref2, actions2) => {
        const builder = new ForeignKeyBuilder(() => {
          const foreignColumn = ref2();
          return { columns: [column8], foreignColumns: [foreignColumn] };
        });
        if (actions2.onUpdate) {
          builder.onUpdate(actions2.onUpdate);
        }
        if (actions2.onDelete) {
          builder.onDelete(actions2.onDelete);
        }
        return builder.build(table12);
      })(ref, actions);
    });
  }
}

class MySqlColumn extends Column {
  constructor(table12, config) {
    if (!config.uniqueName) {
      config.uniqueName = uniqueKeyName(table12, [config.name]);
    }
    super(table12, config);
    this.table = table12;
  }
  static [entityKind] = "MySqlColumn";
}

class MySqlColumnBuilderWithAutoIncrement extends MySqlColumnBuilder {
  static [entityKind] = "MySqlColumnBuilderWithAutoIncrement";
  constructor(name, dataType, columnType) {
    super(name, dataType, columnType);
    this.config.autoIncrement = false;
  }
  autoincrement() {
    this.config.autoIncrement = true;
    this.config.hasDefault = true;
    return this;
  }
}

class MySqlColumnWithAutoIncrement extends MySqlColumn {
  static [entityKind] = "MySqlColumnWithAutoIncrement";
  autoIncrement = this.config.autoIncrement;
}

// node_modules/drizzle-orm/mysql-core/view-base.js
class MySqlViewBase extends View {
  static [entityKind] = "MySqlViewBase";
}

// node_modules/drizzle-orm/mysql-core/dialect.js
class MySqlDialect {
  static [entityKind] = "MySqlDialect";
  async migrate(migrations, session, config) {
    const migrationsTable = config.migrationsTable ?? "__drizzle_migrations";
    const migrationTableCreate = sql2`
			create table if not exists ${sql2.identifier(migrationsTable)} (
				id serial primary key,
				hash text not null,
				created_at bigint
			)
		`;
    await session.execute(migrationTableCreate);
    const dbMigrations = await session.all(sql2`select id, hash, created_at from ${sql2.identifier(migrationsTable)} order by created_at desc limit 1`);
    const lastDbMigration = dbMigrations[0];
    await session.transaction(async (tx) => {
      for (const migration of migrations) {
        if (!lastDbMigration || Number(lastDbMigration.created_at) < migration.folderMillis) {
          for (const stmt of migration.sql) {
            await tx.execute(sql2.raw(stmt));
          }
          await tx.execute(sql2`insert into ${sql2.identifier(migrationsTable)} (\`hash\`, \`created_at\`) values(${migration.hash}, ${migration.folderMillis})`);
        }
      }
    });
  }
  escapeName(name) {
    return `\`${name}\``;
  }
  escapeParam(_num) {
    return `?`;
  }
  escapeString(str) {
    return `'${str.replace(/'/g, "''")}'`;
  }
  buildDeleteQuery({ table: table14, where, returning }) {
    const returningSql = returning ? sql2` returning ${this.buildSelection(returning, { isSingleTable: true })}` : undefined;
    const whereSql = where ? sql2` where ${where}` : undefined;
    return sql2`delete from ${table14}${whereSql}${returningSql}`;
  }
  buildUpdateSet(table14, set) {
    const setEntries = Object.entries(set);
    const setSize = setEntries.length;
    return sql2.join(setEntries.flatMap(([colName, value], i) => {
      const col = table14[Table.Symbol.Columns][colName];
      const res = sql2`${sql2.identifier(col.name)} = ${value}`;
      if (i < setSize - 1) {
        return [res, sql2.raw(", ")];
      }
      return [res];
    }));
  }
  buildUpdateQuery({ table: table14, set, where, returning }) {
    const setSql = this.buildUpdateSet(table14, set);
    const returningSql = returning ? sql2` returning ${this.buildSelection(returning, { isSingleTable: true })}` : undefined;
    const whereSql = where ? sql2` where ${where}` : undefined;
    return sql2`update ${table14} set ${setSql}${whereSql}${returningSql}`;
  }
  buildSelection(fields, { isSingleTable = false } = {}) {
    const columnsLen = fields.length;
    const chunks = fields.flatMap(({ field }, i) => {
      const chunk = [];
      if (is(field, SQL.Aliased) && field.isSelectionField) {
        chunk.push(sql2.identifier(field.fieldAlias));
      } else if (is(field, SQL.Aliased) || is(field, SQL)) {
        const query = is(field, SQL.Aliased) ? field.sql : field;
        if (isSingleTable) {
          chunk.push(new SQL(query.queryChunks.map((c) => {
            if (is(c, MySqlColumn)) {
              return sql2.identifier(c.name);
            }
            return c;
          })));
        } else {
          chunk.push(query);
        }
        if (is(field, SQL.Aliased)) {
          chunk.push(sql2` as ${sql2.identifier(field.fieldAlias)}`);
        }
      } else if (is(field, Column)) {
        if (isSingleTable) {
          chunk.push(sql2.identifier(field.name));
        } else {
          chunk.push(field);
        }
      }
      if (i < columnsLen - 1) {
        chunk.push(sql2`, `);
      }
      return chunk;
    });
    return sql2.join(chunks);
  }
  buildSelectQuery({
    withList,
    fields,
    fieldsFlat,
    where,
    having,
    table: table14,
    joins,
    orderBy,
    groupBy,
    limit,
    offset,
    lockingClause,
    distinct,
    setOperators
  }) {
    const fieldsList = fieldsFlat ?? orderSelectedFields(fields);
    for (const f of fieldsList) {
      if (is(f.field, Column) && getTableName(f.field.table) !== (is(table14, Subquery) ? table14[SubqueryConfig].alias : is(table14, MySqlViewBase) ? table14[ViewBaseConfig].name : is(table14, SQL) ? undefined : getTableName(table14)) && !((table22) => joins?.some(({ alias: alias3 }) => alias3 === (table22[Table.Symbol.IsAlias] ? getTableName(table22) : table22[Table.Symbol.BaseName])))(f.field.table)) {
        const tableName = getTableName(f.field.table);
        throw new Error(`Your "${f.path.join("->")}" field references a column "${tableName}"."${f.field.name}", but the table "${tableName}" is not part of the query! Did you forget to join it?`);
      }
    }
    const isSingleTable = !joins || joins.length === 0;
    let withSql;
    if (withList?.length) {
      const withSqlChunks = [sql2`with `];
      for (const [i, w] of withList.entries()) {
        withSqlChunks.push(sql2`${sql2.identifier(w[SubqueryConfig].alias)} as (${w[SubqueryConfig].sql})`);
        if (i < withList.length - 1) {
          withSqlChunks.push(sql2`, `);
        }
      }
      withSqlChunks.push(sql2` `);
      withSql = sql2.join(withSqlChunks);
    }
    const distinctSql = distinct ? sql2` distinct` : undefined;
    const selection = this.buildSelection(fieldsList, { isSingleTable });
    const tableSql = (() => {
      if (is(table14, Table) && table14[Table.Symbol.OriginalName] !== table14[Table.Symbol.Name]) {
        return sql2`${sql2.identifier(table14[Table.Symbol.OriginalName])} ${sql2.identifier(table14[Table.Symbol.Name])}`;
      }
      return table14;
    })();
    const joinsArray = [];
    if (joins) {
      for (const [index, joinMeta] of joins.entries()) {
        if (index === 0) {
          joinsArray.push(sql2` `);
        }
        const table22 = joinMeta.table;
        const lateralSql = joinMeta.lateral ? sql2` lateral` : undefined;
        if (is(table22, MySqlTable)) {
          const tableName = table22[MySqlTable.Symbol.Name];
          const tableSchema = table22[MySqlTable.Symbol.Schema];
          const origTableName = table22[MySqlTable.Symbol.OriginalName];
          const alias3 = tableName === origTableName ? undefined : joinMeta.alias;
          joinsArray.push(sql2`${sql2.raw(joinMeta.joinType)} join${lateralSql} ${tableSchema ? sql2`${sql2.identifier(tableSchema)}.` : undefined}${sql2.identifier(origTableName)}${alias3 && sql2` ${sql2.identifier(alias3)}`} on ${joinMeta.on}`);
        } else if (is(table22, View)) {
          const viewName = table22[ViewBaseConfig].name;
          const viewSchema = table22[ViewBaseConfig].schema;
          const origViewName = table22[ViewBaseConfig].originalName;
          const alias3 = viewName === origViewName ? undefined : joinMeta.alias;
          joinsArray.push(sql2`${sql2.raw(joinMeta.joinType)} join${lateralSql} ${viewSchema ? sql2`${sql2.identifier(viewSchema)}.` : undefined}${sql2.identifier(origViewName)}${alias3 && sql2` ${sql2.identifier(alias3)}`} on ${joinMeta.on}`);
        } else {
          joinsArray.push(sql2`${sql2.raw(joinMeta.joinType)} join${lateralSql} ${table22} on ${joinMeta.on}`);
        }
        if (index < joins.length - 1) {
          joinsArray.push(sql2` `);
        }
      }
    }
    const joinsSql = sql2.join(joinsArray);
    const whereSql = where ? sql2` where ${where}` : undefined;
    const havingSql = having ? sql2` having ${having}` : undefined;
    let orderBySql;
    if (orderBy && orderBy.length > 0) {
      orderBySql = sql2` order by ${sql2.join(orderBy, sql2`, `)}`;
    }
    let groupBySql;
    if (groupBy && groupBy.length > 0) {
      groupBySql = sql2` group by ${sql2.join(groupBy, sql2`, `)}`;
    }
    const limitSql = limit ? sql2` limit ${limit}` : undefined;
    const offsetSql = offset ? sql2` offset ${offset}` : undefined;
    let lockingClausesSql;
    if (lockingClause) {
      const { config, strength } = lockingClause;
      lockingClausesSql = sql2` for ${sql2.raw(strength)}`;
      if (config.noWait) {
        lockingClausesSql.append(sql2` no wait`);
      } else if (config.skipLocked) {
        lockingClausesSql.append(sql2` skip locked`);
      }
    }
    const finalQuery = sql2`${withSql}select${distinctSql} ${selection} from ${tableSql}${joinsSql}${whereSql}${groupBySql}${havingSql}${orderBySql}${limitSql}${offsetSql}${lockingClausesSql}`;
    if (setOperators.length > 0) {
      return this.buildSetOperations(finalQuery, setOperators);
    }
    return finalQuery;
  }
  buildSetOperations(leftSelect, setOperators) {
    const [setOperator, ...rest] = setOperators;
    if (!setOperator) {
      throw new Error("Cannot pass undefined values to any set operator");
    }
    if (rest.length === 0) {
      return this.buildSetOperationQuery({ leftSelect, setOperator });
    }
    return this.buildSetOperations(this.buildSetOperationQuery({ leftSelect, setOperator }), rest);
  }
  buildSetOperationQuery({
    leftSelect,
    setOperator: { type, isAll, rightSelect, limit, orderBy, offset }
  }) {
    const leftChunk = sql2`(${leftSelect.getSQL()}) `;
    const rightChunk = sql2`(${rightSelect.getSQL()})`;
    let orderBySql;
    if (orderBy && orderBy.length > 0) {
      const orderByValues = [];
      for (const orderByUnit of orderBy) {
        if (is(orderByUnit, MySqlColumn)) {
          orderByValues.push(sql2.identifier(orderByUnit.name));
        } else if (is(orderByUnit, SQL)) {
          for (let i = 0;i < orderByUnit.queryChunks.length; i++) {
            const chunk = orderByUnit.queryChunks[i];
            if (is(chunk, MySqlColumn)) {
              orderByUnit.queryChunks[i] = sql2.identifier(chunk.name);
            }
          }
          orderByValues.push(sql2`${orderByUnit}`);
        } else {
          orderByValues.push(sql2`${orderByUnit}`);
        }
      }
      orderBySql = sql2` order by ${sql2.join(orderByValues, sql2`, `)} `;
    }
    const limitSql = limit ? sql2` limit ${limit}` : undefined;
    const operatorChunk = sql2.raw(`${type} ${isAll ? "all " : ""}`);
    const offsetSql = offset ? sql2` offset ${offset}` : undefined;
    return sql2`${leftChunk}${operatorChunk}${rightChunk}${orderBySql}${limitSql}${offsetSql}`;
  }
  buildInsertQuery({ table: table14, values, ignore, onConflict }) {
    const valuesSqlList = [];
    const columns = table14[Table.Symbol.Columns];
    const colEntries = Object.entries(columns);
    const insertOrder = colEntries.map(([, column9]) => sql2.identifier(column9.name));
    for (const [valueIndex, value] of values.entries()) {
      const valueList = [];
      for (const [fieldName, col] of colEntries) {
        const colValue = value[fieldName];
        if (colValue === undefined || is(colValue, Param) && colValue.value === undefined) {
          if (col.defaultFn !== undefined) {
            const defaultFnResult = col.defaultFn();
            const defaultValue = is(defaultFnResult, SQL) ? defaultFnResult : sql2.param(defaultFnResult, col);
            valueList.push(defaultValue);
          } else {
            valueList.push(sql2`default`);
          }
        } else {
          valueList.push(colValue);
        }
      }
      valuesSqlList.push(valueList);
      if (valueIndex < values.length - 1) {
        valuesSqlList.push(sql2`, `);
      }
    }
    const valuesSql = sql2.join(valuesSqlList);
    const ignoreSql = ignore ? sql2` ignore` : undefined;
    const onConflictSql = onConflict ? sql2` on duplicate key ${onConflict}` : undefined;
    return sql2`insert${ignoreSql} into ${table14} ${insertOrder} values ${valuesSql}${onConflictSql}`;
  }
  sqlToQuery(sql22) {
    return sql22.toQuery({
      escapeName: this.escapeName,
      escapeParam: this.escapeParam,
      escapeString: this.escapeString
    });
  }
  buildRelationalQuery({
    fullSchema,
    schema,
    tableNamesMap,
    table: table14,
    tableConfig,
    queryConfig: config,
    tableAlias,
    nestedQueryRelation,
    joinOn
  }) {
    let selection = [];
    let limit, offset, orderBy, where;
    const joins = [];
    if (config === true) {
      const selectionEntries = Object.entries(tableConfig.columns);
      selection = selectionEntries.map(([key, value]) => ({
        dbKey: value.name,
        tsKey: key,
        field: aliasedTableColumn(value, tableAlias),
        relationTableTsKey: undefined,
        isJson: false,
        selection: []
      }));
    } else {
      const aliasedColumns = Object.fromEntries(Object.entries(tableConfig.columns).map(([key, value]) => [key, aliasedTableColumn(value, tableAlias)]));
      if (config.where) {
        const whereSql = typeof config.where === "function" ? config.where(aliasedColumns, getOperators()) : config.where;
        where = whereSql && mapColumnsInSQLToAlias(whereSql, tableAlias);
      }
      const fieldsSelection = [];
      let selectedColumns = [];
      if (config.columns) {
        let isIncludeMode = false;
        for (const [field, value] of Object.entries(config.columns)) {
          if (value === undefined) {
            continue;
          }
          if (field in tableConfig.columns) {
            if (!isIncludeMode && value === true) {
              isIncludeMode = true;
            }
            selectedColumns.push(field);
          }
        }
        if (selectedColumns.length > 0) {
          selectedColumns = isIncludeMode ? selectedColumns.filter((c) => config.columns?.[c] === true) : Object.keys(tableConfig.columns).filter((key) => !selectedColumns.includes(key));
        }
      } else {
        selectedColumns = Object.keys(tableConfig.columns);
      }
      for (const field of selectedColumns) {
        const column9 = tableConfig.columns[field];
        fieldsSelection.push({ tsKey: field, value: column9 });
      }
      let selectedRelations = [];
      if (config.with) {
        selectedRelations = Object.entries(config.with).filter((entry) => !!entry[1]).map(([tsKey, queryConfig]) => ({ tsKey, queryConfig, relation: tableConfig.relations[tsKey] }));
      }
      let extras;
      if (config.extras) {
        extras = typeof config.extras === "function" ? config.extras(aliasedColumns, { sql: sql2 }) : config.extras;
        for (const [tsKey, value] of Object.entries(extras)) {
          fieldsSelection.push({
            tsKey,
            value: mapColumnsInAliasedSQLToAlias(value, tableAlias)
          });
        }
      }
      for (const { tsKey, value } of fieldsSelection) {
        selection.push({
          dbKey: is(value, SQL.Aliased) ? value.fieldAlias : tableConfig.columns[tsKey].name,
          tsKey,
          field: is(value, Column) ? aliasedTableColumn(value, tableAlias) : value,
          relationTableTsKey: undefined,
          isJson: false,
          selection: []
        });
      }
      let orderByOrig = typeof config.orderBy === "function" ? config.orderBy(aliasedColumns, getOrderByOperators()) : config.orderBy ?? [];
      if (!Array.isArray(orderByOrig)) {
        orderByOrig = [orderByOrig];
      }
      orderBy = orderByOrig.map((orderByValue) => {
        if (is(orderByValue, Column)) {
          return aliasedTableColumn(orderByValue, tableAlias);
        }
        return mapColumnsInSQLToAlias(orderByValue, tableAlias);
      });
      limit = config.limit;
      offset = config.offset;
      for (const {
        tsKey: selectedRelationTsKey,
        queryConfig: selectedRelationConfigValue,
        relation
      } of selectedRelations) {
        const normalizedRelation = normalizeRelation(schema, tableNamesMap, relation);
        const relationTableName = relation.referencedTable[Table.Symbol.Name];
        const relationTableTsName = tableNamesMap[relationTableName];
        const relationTableAlias = `${tableAlias}_${selectedRelationTsKey}`;
        const joinOn2 = and(...normalizedRelation.fields.map((field2, i) => eq(aliasedTableColumn(normalizedRelation.references[i], relationTableAlias), aliasedTableColumn(field2, tableAlias))));
        const builtRelation = this.buildRelationalQuery({
          fullSchema,
          schema,
          tableNamesMap,
          table: fullSchema[relationTableTsName],
          tableConfig: schema[relationTableTsName],
          queryConfig: is(relation, One) ? selectedRelationConfigValue === true ? { limit: 1 } : { ...selectedRelationConfigValue, limit: 1 } : selectedRelationConfigValue,
          tableAlias: relationTableAlias,
          joinOn: joinOn2,
          nestedQueryRelation: relation
        });
        const field = sql2`${sql2.identifier(relationTableAlias)}.${sql2.identifier("data")}`.as(selectedRelationTsKey);
        joins.push({
          on: sql2`true`,
          table: new Subquery(builtRelation.sql, {}, relationTableAlias),
          alias: relationTableAlias,
          joinType: "left",
          lateral: true
        });
        selection.push({
          dbKey: selectedRelationTsKey,
          tsKey: selectedRelationTsKey,
          field,
          relationTableTsKey: relationTableTsName,
          isJson: true,
          selection: builtRelation.selection
        });
      }
    }
    if (selection.length === 0) {
      throw new DrizzleError({ message: `No fields selected for table "${tableConfig.tsName}" ("${tableAlias}")` });
    }
    let result;
    where = and(joinOn, where);
    if (nestedQueryRelation) {
      let field = sql2`json_array(${sql2.join(selection.map(({ field: field2, tsKey, isJson }) => isJson ? sql2`${sql2.identifier(`${tableAlias}_${tsKey}`)}.${sql2.identifier("data")}` : is(field2, SQL.Aliased) ? field2.sql : field2), sql2`, `)})`;
      if (is(nestedQueryRelation, Many)) {
        field = sql2`coalesce(json_arrayagg(${field}), json_array())`;
      }
      const nestedSelection = [{
        dbKey: "data",
        tsKey: "data",
        field: field.as("data"),
        isJson: true,
        relationTableTsKey: tableConfig.tsName,
        selection
      }];
      const needsSubquery = limit !== undefined || offset !== undefined || (orderBy?.length ?? 0) > 0;
      if (needsSubquery) {
        result = this.buildSelectQuery({
          table: aliasedTable(table14, tableAlias),
          fields: {},
          fieldsFlat: [
            {
              path: [],
              field: sql2.raw("*")
            },
            ...(orderBy?.length ?? 0) > 0 ? [{
              path: [],
              field: sql2`row_number() over (order by ${sql2.join(orderBy, sql2`, `)})`
            }] : []
          ],
          where,
          limit,
          offset,
          setOperators: []
        });
        where = undefined;
        limit = undefined;
        offset = undefined;
        orderBy = undefined;
      } else {
        result = aliasedTable(table14, tableAlias);
      }
      result = this.buildSelectQuery({
        table: is(result, MySqlTable) ? result : new Subquery(result, {}, tableAlias),
        fields: {},
        fieldsFlat: nestedSelection.map(({ field: field2 }) => ({
          path: [],
          field: is(field2, Column) ? aliasedTableColumn(field2, tableAlias) : field2
        })),
        joins,
        where,
        limit,
        offset,
        orderBy,
        setOperators: []
      });
    } else {
      result = this.buildSelectQuery({
        table: aliasedTable(table14, tableAlias),
        fields: {},
        fieldsFlat: selection.map(({ field }) => ({
          path: [],
          field: is(field, Column) ? aliasedTableColumn(field, tableAlias) : field
        })),
        joins,
        where,
        limit,
        offset,
        orderBy,
        setOperators: []
      });
    }
    return {
      tableTsKey: tableConfig.tsName,
      sql: result,
      selection
    };
  }
  buildRelationalQueryWithoutLateralSubqueries({
    fullSchema,
    schema,
    tableNamesMap,
    table: table14,
    tableConfig,
    queryConfig: config,
    tableAlias,
    nestedQueryRelation,
    joinOn
  }) {
    let selection = [];
    let limit, offset, orderBy = [], where;
    if (config === true) {
      const selectionEntries = Object.entries(tableConfig.columns);
      selection = selectionEntries.map(([key, value]) => ({
        dbKey: value.name,
        tsKey: key,
        field: aliasedTableColumn(value, tableAlias),
        relationTableTsKey: undefined,
        isJson: false,
        selection: []
      }));
    } else {
      const aliasedColumns = Object.fromEntries(Object.entries(tableConfig.columns).map(([key, value]) => [key, aliasedTableColumn(value, tableAlias)]));
      if (config.where) {
        const whereSql = typeof config.where === "function" ? config.where(aliasedColumns, getOperators()) : config.where;
        where = whereSql && mapColumnsInSQLToAlias(whereSql, tableAlias);
      }
      const fieldsSelection = [];
      let selectedColumns = [];
      if (config.columns) {
        let isIncludeMode = false;
        for (const [field, value] of Object.entries(config.columns)) {
          if (value === undefined) {
            continue;
          }
          if (field in tableConfig.columns) {
            if (!isIncludeMode && value === true) {
              isIncludeMode = true;
            }
            selectedColumns.push(field);
          }
        }
        if (selectedColumns.length > 0) {
          selectedColumns = isIncludeMode ? selectedColumns.filter((c) => config.columns?.[c] === true) : Object.keys(tableConfig.columns).filter((key) => !selectedColumns.includes(key));
        }
      } else {
        selectedColumns = Object.keys(tableConfig.columns);
      }
      for (const field of selectedColumns) {
        const column9 = tableConfig.columns[field];
        fieldsSelection.push({ tsKey: field, value: column9 });
      }
      let selectedRelations = [];
      if (config.with) {
        selectedRelations = Object.entries(config.with).filter((entry) => !!entry[1]).map(([tsKey, queryConfig]) => ({ tsKey, queryConfig, relation: tableConfig.relations[tsKey] }));
      }
      let extras;
      if (config.extras) {
        extras = typeof config.extras === "function" ? config.extras(aliasedColumns, { sql: sql2 }) : config.extras;
        for (const [tsKey, value] of Object.entries(extras)) {
          fieldsSelection.push({
            tsKey,
            value: mapColumnsInAliasedSQLToAlias(value, tableAlias)
          });
        }
      }
      for (const { tsKey, value } of fieldsSelection) {
        selection.push({
          dbKey: is(value, SQL.Aliased) ? value.fieldAlias : tableConfig.columns[tsKey].name,
          tsKey,
          field: is(value, Column) ? aliasedTableColumn(value, tableAlias) : value,
          relationTableTsKey: undefined,
          isJson: false,
          selection: []
        });
      }
      let orderByOrig = typeof config.orderBy === "function" ? config.orderBy(aliasedColumns, getOrderByOperators()) : config.orderBy ?? [];
      if (!Array.isArray(orderByOrig)) {
        orderByOrig = [orderByOrig];
      }
      orderBy = orderByOrig.map((orderByValue) => {
        if (is(orderByValue, Column)) {
          return aliasedTableColumn(orderByValue, tableAlias);
        }
        return mapColumnsInSQLToAlias(orderByValue, tableAlias);
      });
      limit = config.limit;
      offset = config.offset;
      for (const {
        tsKey: selectedRelationTsKey,
        queryConfig: selectedRelationConfigValue,
        relation
      } of selectedRelations) {
        const normalizedRelation = normalizeRelation(schema, tableNamesMap, relation);
        const relationTableName = relation.referencedTable[Table.Symbol.Name];
        const relationTableTsName = tableNamesMap[relationTableName];
        const relationTableAlias = `${tableAlias}_${selectedRelationTsKey}`;
        const joinOn2 = and(...normalizedRelation.fields.map((field2, i) => eq(aliasedTableColumn(normalizedRelation.references[i], relationTableAlias), aliasedTableColumn(field2, tableAlias))));
        const builtRelation = this.buildRelationalQueryWithoutLateralSubqueries({
          fullSchema,
          schema,
          tableNamesMap,
          table: fullSchema[relationTableTsName],
          tableConfig: schema[relationTableTsName],
          queryConfig: is(relation, One) ? selectedRelationConfigValue === true ? { limit: 1 } : { ...selectedRelationConfigValue, limit: 1 } : selectedRelationConfigValue,
          tableAlias: relationTableAlias,
          joinOn: joinOn2,
          nestedQueryRelation: relation
        });
        let fieldSql = sql2`(${builtRelation.sql})`;
        if (is(relation, Many)) {
          fieldSql = sql2`coalesce(${fieldSql}, json_array())`;
        }
        const field = fieldSql.as(selectedRelationTsKey);
        selection.push({
          dbKey: selectedRelationTsKey,
          tsKey: selectedRelationTsKey,
          field,
          relationTableTsKey: relationTableTsName,
          isJson: true,
          selection: builtRelation.selection
        });
      }
    }
    if (selection.length === 0) {
      throw new DrizzleError({
        message: `No fields selected for table "${tableConfig.tsName}" ("${tableAlias}"). You need to have at least one item in "columns", "with" or "extras". If you need to select all columns, omit the "columns" key or set it to undefined.`
      });
    }
    let result;
    where = and(joinOn, where);
    if (nestedQueryRelation) {
      let field = sql2`json_array(${sql2.join(selection.map(({ field: field2 }) => is(field2, MySqlColumn) ? sql2.identifier(field2.name) : is(field2, SQL.Aliased) ? field2.sql : field2), sql2`, `)})`;
      if (is(nestedQueryRelation, Many)) {
        field = sql2`json_arrayagg(${field})`;
      }
      const nestedSelection = [{
        dbKey: "data",
        tsKey: "data",
        field,
        isJson: true,
        relationTableTsKey: tableConfig.tsName,
        selection
      }];
      const needsSubquery = limit !== undefined || offset !== undefined || orderBy.length > 0;
      if (needsSubquery) {
        result = this.buildSelectQuery({
          table: aliasedTable(table14, tableAlias),
          fields: {},
          fieldsFlat: [
            {
              path: [],
              field: sql2.raw("*")
            },
            ...orderBy.length > 0 ? [{
              path: [],
              field: sql2`row_number() over (order by ${sql2.join(orderBy, sql2`, `)})`
            }] : []
          ],
          where,
          limit,
          offset,
          setOperators: []
        });
        where = undefined;
        limit = undefined;
        offset = undefined;
        orderBy = undefined;
      } else {
        result = aliasedTable(table14, tableAlias);
      }
      result = this.buildSelectQuery({
        table: is(result, MySqlTable) ? result : new Subquery(result, {}, tableAlias),
        fields: {},
        fieldsFlat: nestedSelection.map(({ field: field2 }) => ({
          path: [],
          field: is(field2, Column) ? aliasedTableColumn(field2, tableAlias) : field2
        })),
        where,
        limit,
        offset,
        orderBy,
        setOperators: []
      });
    } else {
      result = this.buildSelectQuery({
        table: aliasedTable(table14, tableAlias),
        fields: {},
        fieldsFlat: selection.map(({ field }) => ({
          path: [],
          field: is(field, Column) ? aliasedTableColumn(field, tableAlias) : field
        })),
        where,
        limit,
        offset,
        orderBy,
        setOperators: []
      });
    }
    return {
      tableTsKey: tableConfig.tsName,
      sql: result,
      selection
    };
  }
}

// node_modules/drizzle-orm/query-builders/query-builder.js
class TypedQueryBuilder {
  static [entityKind] = "TypedQueryBuilder";
  getSelectedFields() {
    return this._.selectedFields;
  }
}

// node_modules/drizzle-orm/mysql-core/query-builders/select.js
var createSetOperator = function(type, isAll) {
  return (leftSelect, rightSelect, ...restSelects) => {
    const setOperators = [rightSelect, ...restSelects].map((select) => ({
      type,
      isAll,
      rightSelect: select
    }));
    for (const setOperator of setOperators) {
      if (!haveSameKeys(leftSelect.getSelectedFields(), setOperator.rightSelect.getSelectedFields())) {
        throw new Error("Set operator error (union / intersect / except): selected fields are not the same or are in a different order");
      }
    }
    return leftSelect.addSetOperators(setOperators);
  };
};

class MySqlSelectBuilder {
  static [entityKind] = "MySqlSelectBuilder";
  fields;
  session;
  dialect;
  withList = [];
  distinct;
  constructor(config) {
    this.fields = config.fields;
    this.session = config.session;
    this.dialect = config.dialect;
    if (config.withList) {
      this.withList = config.withList;
    }
    this.distinct = config.distinct;
  }
  from(source) {
    const isPartialSelect = !!this.fields;
    let fields;
    if (this.fields) {
      fields = this.fields;
    } else if (is(source, Subquery)) {
      fields = Object.fromEntries(Object.keys(source[SubqueryConfig].selection).map((key) => [key, source[key]]));
    } else if (is(source, MySqlViewBase)) {
      fields = source[ViewBaseConfig].selectedFields;
    } else if (is(source, SQL)) {
      fields = {};
    } else {
      fields = getTableColumns(source);
    }
    return new MySqlSelectBase({
      table: source,
      fields,
      isPartialSelect,
      session: this.session,
      dialect: this.dialect,
      withList: this.withList,
      distinct: this.distinct
    });
  }
}

class MySqlSelectQueryBuilderBase extends TypedQueryBuilder {
  static [entityKind] = "MySqlSelectQueryBuilder";
  _;
  config;
  joinsNotNullableMap;
  tableName;
  isPartialSelect;
  session;
  dialect;
  constructor({ table: table15, fields, isPartialSelect, session, dialect, withList, distinct }) {
    super();
    this.config = {
      withList,
      table: table15,
      fields: { ...fields },
      distinct,
      setOperators: []
    };
    this.isPartialSelect = isPartialSelect;
    this.session = session;
    this.dialect = dialect;
    this._ = {
      selectedFields: fields
    };
    this.tableName = getTableLikeName(table15);
    this.joinsNotNullableMap = typeof this.tableName === "string" ? { [this.tableName]: true } : {};
  }
  createJoin(joinType) {
    return (table15, on) => {
      const baseTableName = this.tableName;
      const tableName = getTableLikeName(table15);
      if (typeof tableName === "string" && this.config.joins?.some((join) => join.alias === tableName)) {
        throw new Error(`Alias "${tableName}" is already used in this query`);
      }
      if (!this.isPartialSelect) {
        if (Object.keys(this.joinsNotNullableMap).length === 1 && typeof baseTableName === "string") {
          this.config.fields = {
            [baseTableName]: this.config.fields
          };
        }
        if (typeof tableName === "string" && !is(table15, SQL)) {
          const selection = is(table15, Subquery) ? table15[SubqueryConfig].selection : is(table15, View) ? table15[ViewBaseConfig].selectedFields : table15[Table.Symbol.Columns];
          this.config.fields[tableName] = selection;
        }
      }
      if (typeof on === "function") {
        on = on(new Proxy(this.config.fields, new SelectionProxyHandler({ sqlAliasedBehavior: "sql", sqlBehavior: "sql" })));
      }
      if (!this.config.joins) {
        this.config.joins = [];
      }
      this.config.joins.push({ on, table: table15, joinType, alias: tableName });
      if (typeof tableName === "string") {
        switch (joinType) {
          case "left": {
            this.joinsNotNullableMap[tableName] = false;
            break;
          }
          case "right": {
            this.joinsNotNullableMap = Object.fromEntries(Object.entries(this.joinsNotNullableMap).map(([key]) => [key, false]));
            this.joinsNotNullableMap[tableName] = true;
            break;
          }
          case "inner": {
            this.joinsNotNullableMap[tableName] = true;
            break;
          }
          case "full": {
            this.joinsNotNullableMap = Object.fromEntries(Object.entries(this.joinsNotNullableMap).map(([key]) => [key, false]));
            this.joinsNotNullableMap[tableName] = false;
            break;
          }
        }
      }
      return this;
    };
  }
  leftJoin = this.createJoin("left");
  rightJoin = this.createJoin("right");
  innerJoin = this.createJoin("inner");
  fullJoin = this.createJoin("full");
  createSetOperator(type, isAll) {
    return (rightSelection) => {
      const rightSelect = typeof rightSelection === "function" ? rightSelection(getMySqlSetOperators()) : rightSelection;
      if (!haveSameKeys(this.getSelectedFields(), rightSelect.getSelectedFields())) {
        throw new Error("Set operator error (union / intersect / except): selected fields are not the same or are in a different order");
      }
      this.config.setOperators.push({ type, isAll, rightSelect });
      return this;
    };
  }
  union = this.createSetOperator("union", false);
  unionAll = this.createSetOperator("union", true);
  intersect = this.createSetOperator("intersect", false);
  intersectAll = this.createSetOperator("intersect", true);
  except = this.createSetOperator("except", false);
  exceptAll = this.createSetOperator("except", true);
  addSetOperators(setOperators) {
    this.config.setOperators.push(...setOperators);
    return this;
  }
  where(where) {
    if (typeof where === "function") {
      where = where(new Proxy(this.config.fields, new SelectionProxyHandler({ sqlAliasedBehavior: "sql", sqlBehavior: "sql" })));
    }
    this.config.where = where;
    return this;
  }
  having(having) {
    if (typeof having === "function") {
      having = having(new Proxy(this.config.fields, new SelectionProxyHandler({ sqlAliasedBehavior: "sql", sqlBehavior: "sql" })));
    }
    this.config.having = having;
    return this;
  }
  groupBy(...columns) {
    if (typeof columns[0] === "function") {
      const groupBy = columns[0](new Proxy(this.config.fields, new SelectionProxyHandler({ sqlAliasedBehavior: "alias", sqlBehavior: "sql" })));
      this.config.groupBy = Array.isArray(groupBy) ? groupBy : [groupBy];
    } else {
      this.config.groupBy = columns;
    }
    return this;
  }
  orderBy(...columns) {
    if (typeof columns[0] === "function") {
      const orderBy = columns[0](new Proxy(this.config.fields, new SelectionProxyHandler({ sqlAliasedBehavior: "alias", sqlBehavior: "sql" })));
      const orderByArray = Array.isArray(orderBy) ? orderBy : [orderBy];
      if (this.config.setOperators.length > 0) {
        this.config.setOperators.at(-1).orderBy = orderByArray;
      } else {
        this.config.orderBy = orderByArray;
      }
    } else {
      const orderByArray = columns;
      if (this.config.setOperators.length > 0) {
        this.config.setOperators.at(-1).orderBy = orderByArray;
      } else {
        this.config.orderBy = orderByArray;
      }
    }
    return this;
  }
  limit(limit) {
    if (this.config.setOperators.length > 0) {
      this.config.setOperators.at(-1).limit = limit;
    } else {
      this.config.limit = limit;
    }
    return this;
  }
  offset(offset) {
    if (this.config.setOperators.length > 0) {
      this.config.setOperators.at(-1).offset = offset;
    } else {
      this.config.offset = offset;
    }
    return this;
  }
  for(strength, config = {}) {
    this.config.lockingClause = { strength, config };
    return this;
  }
  getSQL() {
    return this.dialect.buildSelectQuery(this.config);
  }
  toSQL() {
    const { typings: _typings, ...rest } = this.dialect.sqlToQuery(this.getSQL());
    return rest;
  }
  as(alias3) {
    return new Proxy(new Subquery(this.getSQL(), this.config.fields, alias3), new SelectionProxyHandler({ alias: alias3, sqlAliasedBehavior: "alias", sqlBehavior: "error" }));
  }
  getSelectedFields() {
    return new Proxy(this.config.fields, new SelectionProxyHandler({ alias: this.tableName, sqlAliasedBehavior: "alias", sqlBehavior: "error" }));
  }
  $dynamic() {
    return this;
  }
}

class MySqlSelectBase extends MySqlSelectQueryBuilderBase {
  static [entityKind] = "MySqlSelect";
  prepare() {
    if (!this.session) {
      throw new Error("Cannot execute a query on a query builder. Please use a database instance instead.");
    }
    const fieldsList = orderSelectedFields(this.config.fields);
    const query = this.session.prepareQuery(this.dialect.sqlToQuery(this.getSQL()), fieldsList);
    query.joinsNotNullableMap = this.joinsNotNullableMap;
    return query;
  }
  execute = (placeholderValues) => {
    return this.prepare().execute(placeholderValues);
  };
  createIterator = () => {
    const self = this;
    return async function* (placeholderValues) {
      yield* self.prepare().iterator(placeholderValues);
    };
  };
  iterator = this.createIterator();
}
applyMixins(MySqlSelectBase, [QueryPromise]);
var getMySqlSetOperators = () => ({
  union,
  unionAll,
  intersect,
  intersectAll,
  except,
  exceptAll
});
var union = createSetOperator("union", false);
var unionAll = createSetOperator("union", true);
var intersect = createSetOperator("intersect", false);
var intersectAll = createSetOperator("intersect", true);
var except = createSetOperator("except", false);
var exceptAll = createSetOperator("except", true);

// node_modules/drizzle-orm/mysql-core/query-builders/query-builder.js
class QueryBuilder {
  static [entityKind] = "MySqlQueryBuilder";
  dialect;
  $with(alias3) {
    const queryBuilder = this;
    return {
      as(qb) {
        if (typeof qb === "function") {
          qb = qb(queryBuilder);
        }
        return new Proxy(new WithSubquery(qb.getSQL(), qb.getSelectedFields(), alias3, true), new SelectionProxyHandler({ alias: alias3, sqlAliasedBehavior: "alias", sqlBehavior: "error" }));
      }
    };
  }
  with(...queries) {
    const self = this;
    function select2(fields) {
      return new MySqlSelectBuilder({
        fields: fields ?? undefined,
        session: undefined,
        dialect: self.getDialect(),
        withList: queries
      });
    }
    function selectDistinct(fields) {
      return new MySqlSelectBuilder({
        fields: fields ?? undefined,
        session: undefined,
        dialect: self.getDialect(),
        withList: queries,
        distinct: true
      });
    }
    return { select: select2, selectDistinct };
  }
  select(fields) {
    return new MySqlSelectBuilder({ fields: fields ?? undefined, session: undefined, dialect: this.getDialect() });
  }
  selectDistinct(fields) {
    return new MySqlSelectBuilder({
      fields: fields ?? undefined,
      session: undefined,
      dialect: this.getDialect(),
      distinct: true
    });
  }
  getDialect() {
    if (!this.dialect) {
      this.dialect = new MySqlDialect;
    }
    return this.dialect;
  }
}

// node_modules/drizzle-orm/mysql-core/query-builders/update.js
class MySqlUpdateBuilder {
  constructor(table15, session, dialect2) {
    this.table = table15;
    this.session = session;
    this.dialect = dialect2;
  }
  static [entityKind] = "MySqlUpdateBuilder";
  set(values) {
    return new MySqlUpdateBase(this.table, mapUpdateSet(this.table, values), this.session, this.dialect);
  }
}

class MySqlUpdateBase extends QueryPromise {
  constructor(table15, set, session, dialect2) {
    super();
    this.session = session;
    this.dialect = dialect2;
    this.config = { set, table: table15 };
  }
  static [entityKind] = "MySqlUpdate";
  config;
  where(where) {
    this.config.where = where;
    return this;
  }
  getSQL() {
    return this.dialect.buildUpdateQuery(this.config);
  }
  toSQL() {
    const { typings: _typings, ...rest } = this.dialect.sqlToQuery(this.getSQL());
    return rest;
  }
  prepare() {
    return this.session.prepareQuery(this.dialect.sqlToQuery(this.getSQL()), this.config.returning);
  }
  execute = (placeholderValues) => {
    return this.prepare().execute(placeholderValues);
  };
  createIterator = () => {
    const self = this;
    return async function* (placeholderValues) {
      yield* self.prepare().iterator(placeholderValues);
    };
  };
  iterator = this.createIterator();
  $dynamic() {
    return this;
  }
}

// node_modules/drizzle-orm/mysql-core/query-builders/query.js
class RelationalQueryBuilder {
  constructor(fullSchema, schema, tableNamesMap, table15, tableConfig, dialect2, session, mode) {
    this.fullSchema = fullSchema;
    this.schema = schema;
    this.tableNamesMap = tableNamesMap;
    this.table = table15;
    this.tableConfig = tableConfig;
    this.dialect = dialect2;
    this.session = session;
    this.mode = mode;
  }
  static [entityKind] = "MySqlRelationalQueryBuilder";
  findMany(config) {
    return new MySqlRelationalQuery(this.fullSchema, this.schema, this.tableNamesMap, this.table, this.tableConfig, this.dialect, this.session, config ? config : {}, "many", this.mode);
  }
  findFirst(config) {
    return new MySqlRelationalQuery(this.fullSchema, this.schema, this.tableNamesMap, this.table, this.tableConfig, this.dialect, this.session, config ? { ...config, limit: 1 } : { limit: 1 }, "first", this.mode);
  }
}

class MySqlRelationalQuery extends QueryPromise {
  constructor(fullSchema, schema, tableNamesMap, table15, tableConfig, dialect2, session, config, queryMode, mode) {
    super();
    this.fullSchema = fullSchema;
    this.schema = schema;
    this.tableNamesMap = tableNamesMap;
    this.table = table15;
    this.tableConfig = tableConfig;
    this.dialect = dialect2;
    this.session = session;
    this.config = config;
    this.queryMode = queryMode;
    this.mode = mode;
  }
  static [entityKind] = "MySqlRelationalQuery";
  prepare() {
    const { query, builtQuery } = this._toSQL();
    return this.session.prepareQuery(builtQuery, undefined, (rawRows) => {
      const rows = rawRows.map((row) => mapRelationalRow(this.schema, this.tableConfig, row, query.selection));
      if (this.queryMode === "first") {
        return rows[0];
      }
      return rows;
    });
  }
  _getQuery() {
    const query = this.mode === "planetscale" ? this.dialect.buildRelationalQueryWithoutLateralSubqueries({
      fullSchema: this.fullSchema,
      schema: this.schema,
      tableNamesMap: this.tableNamesMap,
      table: this.table,
      tableConfig: this.tableConfig,
      queryConfig: this.config,
      tableAlias: this.tableConfig.tsName
    }) : this.dialect.buildRelationalQuery({
      fullSchema: this.fullSchema,
      schema: this.schema,
      tableNamesMap: this.tableNamesMap,
      table: this.table,
      tableConfig: this.tableConfig,
      queryConfig: this.config,
      tableAlias: this.tableConfig.tsName
    });
    return query;
  }
  _toSQL() {
    const query = this._getQuery();
    const builtQuery = this.dialect.sqlToQuery(query.sql);
    return { builtQuery, query };
  }
  getSQL() {
    return this._getQuery().sql;
  }
  toSQL() {
    return this._toSQL().builtQuery;
  }
  execute() {
    return this.prepare().execute();
  }
}

// node_modules/drizzle-orm/mysql-core/db.js
class MySqlDatabase {
  constructor(dialect2, session, schema, mode) {
    this.dialect = dialect2;
    this.session = session;
    this.mode = mode;
    this._ = schema ? { schema: schema.schema, tableNamesMap: schema.tableNamesMap } : { schema: undefined, tableNamesMap: {} };
    this.query = {};
    if (this._.schema) {
      for (const [tableName, columns] of Object.entries(this._.schema)) {
        this.query[tableName] = new RelationalQueryBuilder(schema.fullSchema, this._.schema, this._.tableNamesMap, schema.fullSchema[tableName], columns, dialect2, session, this.mode);
      }
    }
  }
  static [entityKind] = "MySqlDatabase";
  query;
  $with(alias3) {
    return {
      as(qb) {
        if (typeof qb === "function") {
          qb = qb(new QueryBuilder);
        }
        return new Proxy(new WithSubquery(qb.getSQL(), qb.getSelectedFields(), alias3, true), new SelectionProxyHandler({ alias: alias3, sqlAliasedBehavior: "alias", sqlBehavior: "error" }));
      }
    };
  }
  with(...queries) {
    const self = this;
    function select2(fields) {
      return new MySqlSelectBuilder({
        fields: fields ?? undefined,
        session: self.session,
        dialect: self.dialect,
        withList: queries
      });
    }
    function selectDistinct(fields) {
      return new MySqlSelectBuilder({
        fields: fields ?? undefined,
        session: self.session,
        dialect: self.dialect,
        withList: queries,
        distinct: true
      });
    }
    return { select: select2, selectDistinct };
  }
  select(fields) {
    return new MySqlSelectBuilder({ fields: fields ?? undefined, session: this.session, dialect: this.dialect });
  }
  selectDistinct(fields) {
    return new MySqlSelectBuilder({
      fields: fields ?? undefined,
      session: this.session,
      dialect: this.dialect,
      distinct: true
    });
  }
  update(table15) {
    return new MySqlUpdateBuilder(table15, this.session, this.dialect);
  }
  insert(table15) {
    return new MySqlInsertBuilder(table15, this.session, this.dialect);
  }
  delete(table15) {
    return new MySqlDeleteBase(table15, this.session, this.dialect);
  }
  execute(query2) {
    return this.session.execute(query2.getSQL());
  }
  transaction(transaction, config) {
    return this.session.transaction(transaction, config);
  }
}

// node_modules/drizzle-orm/mysql-core/session.js
class PreparedQuery {
  static [entityKind] = "MySqlPreparedQuery";
  joinsNotNullableMap;
}

class MySqlSession {
  constructor(dialect2) {
    this.dialect = dialect2;
  }
  static [entityKind] = "MySqlSession";
  execute(query2) {
    return this.prepareQuery(this.dialect.sqlToQuery(query2), undefined).execute();
  }
  getSetTransactionSQL(config) {
    const parts = [];
    if (config.isolationLevel) {
      parts.push(`isolation level ${config.isolationLevel}`);
    }
    return parts.length ? sql2.join(["set transaction ", parts.join(" ")]) : undefined;
  }
  getStartTransactionSQL(config) {
    const parts = [];
    if (config.withConsistentSnapshot) {
      parts.push("with consistent snapshot");
    }
    if (config.accessMode) {
      parts.push(config.accessMode);
    }
    return parts.length ? sql2.join(["start transaction ", parts.join(" ")]) : undefined;
  }
}

class MySqlTransaction extends MySqlDatabase {
  constructor(dialect2, session, schema, nestedIndex, mode) {
    super(dialect2, session, schema, mode);
    this.schema = schema;
    this.nestedIndex = nestedIndex;
  }
  static [entityKind] = "MySqlTransaction";
  rollback() {
    throw new TransactionRollbackError;
  }
}

// node_modules/drizzle-orm/planetscale-serverless/session.js
class PlanetScalePreparedQuery extends PreparedQuery {
  constructor(client, queryString, params, logger2, fields, customResultMapper) {
    super();
    this.client = client;
    this.queryString = queryString;
    this.params = params;
    this.logger = logger2;
    this.fields = fields;
    this.customResultMapper = customResultMapper;
  }
  static [entityKind] = "PlanetScalePreparedQuery";
  rawQuery = { as: "object" };
  query = { as: "array" };
  async execute(placeholderValues = {}) {
    const params = fillPlaceholders(this.params, placeholderValues);
    this.logger.logQuery(this.queryString, params);
    const { fields, client, queryString, rawQuery, query: query2, joinsNotNullableMap, customResultMapper } = this;
    if (!fields && !customResultMapper) {
      return client.execute(queryString, params, rawQuery);
    }
    const { rows } = await client.execute(queryString, params, query2);
    if (customResultMapper) {
      return customResultMapper(rows);
    }
    return rows.map((row) => mapResultRow(fields, row, joinsNotNullableMap));
  }
  iterator(_placeholderValues) {
    throw new Error("Streaming is not supported by the PlanetScale Serverless driver");
  }
}

class PlanetscaleSession extends MySqlSession {
  constructor(baseClient, dialect2, tx, schema, options = {}) {
    super(dialect2);
    this.baseClient = baseClient;
    this.schema = schema;
    this.options = options;
    this.client = tx ?? baseClient;
    this.logger = options.logger ?? new NoopLogger;
  }
  static [entityKind] = "PlanetscaleSession";
  logger;
  client;
  prepareQuery(query2, fields, customResultMapper) {
    return new PlanetScalePreparedQuery(this.client, query2.sql, query2.params, this.logger, fields, customResultMapper);
  }
  async query(query2, params) {
    this.logger.logQuery(query2, params);
    return await this.client.execute(query2, params, { as: "array" });
  }
  async queryObjects(query2, params) {
    return this.client.execute(query2, params, { as: "object" });
  }
  all(query2) {
    const querySql = this.dialect.sqlToQuery(query2);
    this.logger.logQuery(querySql.sql, querySql.params);
    return this.client.execute(querySql.sql, querySql.params, { as: "object" }).then((eQuery) => eQuery.rows);
  }
  transaction(transaction) {
    return this.baseClient.transaction((pstx) => {
      const session2 = new PlanetscaleSession(this.baseClient, this.dialect, pstx, this.schema, this.options);
      const tx = new PlanetScaleTransaction(this.dialect, session2, this.schema);
      return transaction(tx);
    });
  }
}

class PlanetScaleTransaction extends MySqlTransaction {
  static [entityKind] = "PlanetScaleTransaction";
  constructor(dialect2, session2, schema, nestedIndex = 0) {
    super(dialect2, session2, schema, nestedIndex, "planetscale");
  }
  async transaction(transaction) {
    const savepointName = `sp${this.nestedIndex + 1}`;
    const tx = new PlanetScaleTransaction(this.dialect, this.session, this.schema, this.nestedIndex + 1);
    await tx.execute(sql2.raw(`savepoint ${savepointName}`));
    try {
      const result = await transaction(tx);
      await tx.execute(sql2.raw(`release savepoint ${savepointName}`));
      return result;
    } catch (err) {
      await tx.execute(sql2.raw(`rollback to savepoint ${savepointName}`));
      throw err;
    }
  }
}

// node_modules/drizzle-orm/planetscale-serverless/driver.js
var drizzle = function(client, config = {}) {
  const dialect3 = new MySqlDialect;
  let logger3;
  if (config.logger === true) {
    logger3 = new DefaultLogger;
  } else if (config.logger !== false) {
    logger3 = config.logger;
  }
  let schema;
  if (config.schema) {
    const tablesConfig = extractTablesRelationalConfig(config.schema, createTableRelationsHelpers);
    schema = {
      fullSchema: config.schema,
      schema: tablesConfig.tables,
      tableNamesMap: tablesConfig.tableNamesMap
    };
  }
  const session3 = new PlanetscaleSession(client, dialect3, undefined, schema, { logger: logger3 });
  return new MySqlDatabase(dialect3, session3, schema, "planetscale");
};

// src/drizzle/schema.ts
var exports_schema = {};
__export(exports_schema, {
  users: () => {
    {
      return users;
    }
  }
});

// node_modules/drizzle-orm/mysql-core/columns/int.js
var int = function(name, config) {
  return new MySqlIntBuilder(name, config);
};

class MySqlIntBuilder extends MySqlColumnBuilderWithAutoIncrement {
  static [entityKind] = "MySqlIntBuilder";
  constructor(name, config) {
    super(name, "number", "MySqlInt");
    this.config.unsigned = config ? config.unsigned : false;
  }
  build(table15) {
    return new MySqlInt(table15, this.config);
  }
}

class MySqlInt extends MySqlColumnWithAutoIncrement {
  static [entityKind] = "MySqlInt";
  getSQLType() {
    return `int${this.config.unsigned ? " unsigned" : ""}`;
  }
  mapFromDriverValue(value) {
    if (typeof value === "string") {
      return Number(value);
    }
    return value;
  }
}

// node_modules/drizzle-orm/mysql-core/columns/text.js
var text2 = function(name, config = {}) {
  return new MySqlTextBuilder(name, "text", config);
};
class MySqlTextBuilder extends MySqlColumnBuilder {
  static [entityKind] = "MySqlTextBuilder";
  constructor(name, textType, config) {
    super(name, "string", "MySqlText");
    this.config.textType = textType;
    this.config.enumValues = config.enum;
  }
  build(table15) {
    return new MySqlText(table15, this.config);
  }
}

class MySqlText extends MySqlColumn {
  static [entityKind] = "MySqlText";
  textType = this.config.textType;
  enumValues = this.config.enumValues;
  getSQLType() {
    return this.textType;
  }
}

// src/drizzle/schema.ts
var mysqlTable = mysqlTableCreator((name) => `aws-twitter_${name}`);
var users = mysqlTable("users", {
  id: int("id").primaryKey().autoincrement(),
  name: text2("name").notNull()
});

// src/drizzle/index.ts
var db3 = drizzle(new Client({
  url: process.env.DATABASE_URL
}).connection(), { schema: exports_schema });

// src/index.tsx
var app = new Hono2;
app.get("/", (c) => {
  return c.json({ message: "Hello" });
});
app.get("/test", (c) => {
  return c.json({ res: "This Works I guess" });
});
app.use(cors());
app.get("/getUser", async (c) => {
  const userList = await db3.select().from(users);
  return c.json(userList);
});
var src_default = {
  port: 3000,
  fetch: app.fetch
};
export {
  src_default as default
};
