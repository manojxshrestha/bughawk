import{r as s,j as e}from"./index-C0FN9ayN.js";import{a as w,p as y,b as N,c as k}from"./httpanalyzer-Cl7jQ9ZO.js";import{T as C,a as f,b as z}from"./techniques-Dc4tEWER.js";import{g as d}from"./engine-DgD9Pvvz.js";const A=s.memo(function(){const[i,b]=s.useState(""),[l,u]=s.useState(""),[t,v]=s.useState(null),[o,n]=s.useState("all"),[c,h]=s.useState(""),p=s.useRef(null),g=a=>{n(a),h(""),requestAnimationFrame(()=>p.current?.scrollIntoView({behavior:"smooth",block:"start"}))},j=()=>{const a=[];i.trim()&&w(y(i)).forEach(r=>a.push({...r,src:"request"})),l.trim()&&N(k(l)).forEach(r=>a.push({...r,src:"response"})),v(a)},x=s.useMemo(()=>new Set((t||[]).map(a=>a.cat)),[t]),m=s.useMemo(()=>{const a=c.toLowerCase();return C.filter(r=>(o==="all"||r.cat===o)&&(!a||r.t.toLowerCase().includes(a)))},[o,c]);return e.jsxs("div",{className:"ha-wrap",children:[e.jsx("style",{children:T}),e.jsxs("header",{className:"ha-head",children:[e.jsxs("div",{children:[e.jsx("h1",{children:" HTTP Analyzer"}),e.jsxs("p",{children:["Paste a raw request & response → findings + ",f," techniques"]})]}),e.jsx("button",{className:"ha-btn-primary",onClick:j,children:"Analyze"})]}),e.jsxs("div",{className:"ha-io",children:[e.jsxs("div",{className:"ha-col",children:[e.jsx("div",{className:"ha-label",children:"Raw Request"}),e.jsx("textarea",{className:"ha-area",value:i,onChange:a=>b(a.target.value),spellCheck:"false",wrap:"off",placeholder:`POST /login?next=/ HTTP/1.1
Host: target.com
Cookie: session=...
Content-Type: application/x-www-form-urlencoded

user=a&pass=b`})]}),e.jsxs("div",{className:"ha-col",children:[e.jsx("div",{className:"ha-label",children:"Raw Response"}),e.jsx("textarea",{className:"ha-area",value:l,onChange:a=>u(a.target.value),spellCheck:"false",wrap:"off",placeholder:`HTTP/1.1 200 OK
Content-Type: text/html
Set-Cookie: session=...; Path=/
Access-Control-Allow-Origin: *

<html>...`})]})]}),t&&e.jsxs("section",{className:"ha-panel",children:[e.jsxs("div",{className:"ha-panel-head",children:[e.jsx("strong",{children:"Findings"}),e.jsxs("span",{className:"ha-count",children:[t.length," issue(s)"]})]}),t.length===0&&e.jsx("div",{className:"ha-empty",children:"No issues from the built-in checks. Browse techniques below for manual tests."}),t.map((a,r)=>e.jsxs("div",{className:"ha-find",children:[e.jsx("span",{className:"ha-sev",style:{background:`${d(a.sev)}22`,color:d(a.sev),borderColor:`${d(a.sev)}55`},children:a.sev}),e.jsxs("div",{className:"ha-find-body",children:[e.jsxs("div",{className:"ha-find-title",children:[a.title," ",e.jsx("span",{className:"ha-src",children:a.src})]}),e.jsx("div",{className:"ha-find-detail",children:a.detail}),e.jsxs("div",{className:"ha-find-fix",children:["↳ ",a.fix," ",e.jsxs("button",{className:"ha-link",onClick:()=>g(a.cat),children:["see ",a.cat," techniques →"]})]})]})]},r))]}),e.jsxs("section",{className:"ha-panel",ref:p,children:[e.jsxs("div",{className:"ha-panel-head",children:[e.jsx("strong",{children:"Technique Library"}),e.jsxs("span",{className:"ha-count",children:[m.length," / ",f]}),e.jsx("input",{className:"ha-search",placeholder:"Search techniques…",value:c,onChange:a=>h(a.target.value)})]}),e.jsxs("div",{className:"ha-cats",children:[e.jsx("button",{className:o==="all"?"on":"",onClick:()=>n("all"),children:"all"}),x.size>0&&[...x].map(a=>e.jsxs("button",{className:`ha-rel ${o===a?"on":""}`,onClick:()=>n(a),children:[" ",a]},`r-${a}`)),z.map(a=>e.jsx("button",{className:o===a?"on":"",onClick:()=>n(a),children:a},a))]}),e.jsx("div",{className:"ha-tech-list",children:m.map((a,r)=>e.jsxs("div",{className:"ha-tech",children:[e.jsx("span",{className:"ha-tech-cat",children:a.cat}),e.jsx("code",{className:"ha-tech-t",children:a.t})]},r))})]})]})}),T=`
.ha-wrap { font-family: var(--font-body); color: var(--text-primary); padding: var(--sp-5); max-width: none; }
.ha-head { display: flex; align-items: center; justify-content: space-between; gap: var(--sp-4); margin-bottom: var(--sp-4); flex-wrap: wrap; }
.ha-head h1 { margin: 0; font-family: var(--font-display); font-size: 22px; }
.ha-head p { margin: 2px 0 0; font-size: 13px; color: var(--text2); }
.ha-btn-primary { background: var(--grad); color: #fff; border: none; padding: 10px 22px; border-radius: var(--radius-sm); font-weight: 600; cursor: pointer; box-shadow: var(--glow-purple); }
.ha-io { display: grid; grid-template-columns: 1fr 1fr; gap: var(--sp-4); margin-bottom: var(--sp-4); }
.ha-col { display: flex; flex-direction: column; }
.ha-label { font-size: 13px; font-weight: 600; margin-bottom: 6px; }
.ha-area { width: 100%; box-sizing: border-box; min-height: 220px; padding: 12px; border-radius: var(--radius-sm); border: 1px solid var(--border); background: var(--bg-base); color: var(--text-primary); font-family: var(--font-data); font-size: 12px; outline: none; resize: vertical; white-space: pre; }
.ha-area:focus { border-color: var(--border-active); }
.ha-panel { background: var(--bg-surface); border: 1px solid var(--border); border-radius: var(--radius); padding: var(--sp-4); margin-bottom: var(--sp-4); }
.ha-panel-head { display: flex; align-items: center; gap: 12px; margin-bottom: 12px; }
.ha-count { font-size: 12px; color: var(--text2); }
.ha-search { margin-left: auto; padding: 7px 12px; border-radius: var(--radius-sm); border: 1px solid var(--border); background: var(--bg-base); color: var(--text-primary); font-size: 13px; outline: none; width: 240px; max-width: 50%; }
.ha-empty { color: var(--text2); font-style: italic; }
.ha-find { display: flex; gap: 12px; padding: 10px 0; border-top: 1px solid var(--border); }
.ha-sev { flex-shrink: 0; align-self: flex-start; text-transform: uppercase; font-size: 10px; font-weight: 800; padding: 3px 8px; border-radius: 999px; border: 1px solid; }
.ha-find-title { font-weight: 600; font-size: 13px; }
.ha-src { font-size: 10px; color: var(--text3); text-transform: uppercase; margin-left: 6px; }
.ha-find-detail { font-size: 12px; color: var(--text2); font-family: var(--font-data); word-break: break-all; margin: 2px 0; }
.ha-find-fix { font-size: 12px; color: var(--text2); }
.ha-link { background: none; border: none; color: var(--accent-primary-bright); cursor: pointer; font-size: 12px; padding: 0; }
.ha-cats { display: flex; flex-wrap: wrap; gap: 4px; margin-bottom: 12px; }
.ha-cats button { border: 1px solid var(--border); background: var(--surface); color: var(--text2); padding: 4px 10px; border-radius: 999px; font-size: 11px; cursor: pointer; }
.ha-cats button.on { background: var(--accent-primary-dim); color: var(--accent-primary-bright); border-color: var(--border-active); }
.ha-cats .ha-rel { color: #f59e0b; border-color: rgba(245,158,11,0.4); }
.ha-tech-list { max-height: 520px; overflow: auto; }
.ha-tech { display: flex; gap: 10px; padding: 6px 0; border-top: 1px solid var(--border); }
.ha-tech-cat { flex-shrink: 0; width: 90px; font-size: 10px; color: var(--accent-primary-bright); text-transform: uppercase; font-weight: 700; }
.ha-tech-t { flex: 1; font-family: var(--font-data); font-size: 12px; color: var(--text-primary); white-space: pre-wrap; word-break: break-word; }
@media (max-width: 820px) { .ha-io { grid-template-columns: 1fr; } }
`;export{A as default};
