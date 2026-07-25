function c(n,t=150){let e=null;const l=(...u)=>{e&&clearTimeout(e),e=setTimeout(()=>{e=null,n(...u)},t)};return l.cancel=()=>{e&&clearTimeout(e),e=null},l}export{c as d};
