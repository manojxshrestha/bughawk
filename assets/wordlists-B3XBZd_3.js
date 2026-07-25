import{g as d,K as u,e as w}from"./index-C0FN9ayN.js";function f(e,{dedup:s=!0,sort:o=!1,trim:n=!0}={}){let t=(e||"").split(`
`);return n&&(t=t.map(r=>r.trim())),t=t.filter(Boolean),s&&(t=[...new Set(t)]),o&&t.sort((r,i)=>r.localeCompare(i)),t.join(`
`)}async function g(){const e=await d(u.wordlists,[]);return Array.isArray(e)?e:[]}async function m(e){return await w(u.wordlists,e),e}async function y({name:e,category:s,content:o},n={}){const t=await g(),r=f(o,n),i=(s||"").trim()||"Uncategorized",l=a=>({content:a,lines:a?a.split(`
`).filter(Boolean).length:0,preview:a.split(`
`).slice(0,6).join(`
`)}),c=t.findIndex(a=>a.name===e&&(a.category||"Uncategorized")===i);return c>=0?t[c]={...t[c],...l(f(`${t[c].content}
${r}`,n))}:t.push({id:`wl_${Date.now()}_${Math.random().toString(36).slice(2,6)}`,name:e,category:i,...l(r)}),await m(t),t}function h(e){const s=new Map;for(const n of e)for(const t of new Set(n.content.split(`
`).filter(Boolean)))s.set(t,(s.get(t)||0)+1);let o=0;for(const n of s.values())n>1&&o++;return{uniqueEntries:s.size,sharedEntries:o}}function S(e,s=[]){const o=s.map(n=>String(n).toLowerCase()).filter(Boolean);return o.length===0?[]:e.filter(n=>{const t=`${n.name} ${n.category||""}`.toLowerCase();return o.some(r=>t.includes(r)||r.includes((n.category||"").toLowerCase()))})}export{y as a,S as b,h as c,f as d,g as l,m as s};
