// Simple client-side search using pre-built /index.json
(function(){
  // BLOG PAGE SEARCH
  const blogInput = document.getElementById('blogSearchInput');
  const postsContainer = document.getElementById('postsContainer');
  const stats = document.getElementById('searchStats');
  let indexLoaded = false; let INDEX = [];
  if(blogInput){
    fetch('/index.json').then(r=>r.json()).then(j=>{ INDEX=j; indexLoaded=true; stats && (stats.textContent = `${INDEX.length} posts`); });
    const deb=(fn,ms)=>{let t;return (...a)=>{clearTimeout(t);t=setTimeout(()=>fn(...a),ms)};};
    function filter(){
      const q = blogInput.value.trim().toLowerCase();
      let shown = 0;
      postsContainer.querySelectorAll('.post-card').forEach(card=>{
        if(!q){ card.style.display='flex'; shown++; return; }
        const hay = card.dataset.title+" "+card.dataset.summary+" "+card.dataset.content;
        if(hay.includes(q)){ card.style.display='flex'; shown++; } else card.style.display='none';
      });
      if(stats) stats.textContent = q? `${shown} match${shown===1?'':'es'}` : `${INDEX.length} posts`;
      const none = document.getElementById('noResults');
      if(none) none.style.display = shown? 'none':'block';
    }
    blogInput.addEventListener('input', deb(filter,120));
    document.addEventListener('keydown', e=>{ if(e.key==='/' && document.activeElement!==blogInput){ blogInput.focus(); e.preventDefault(); }});
  }

  // COPY BUTTONS
  function addCopyButtons(){
    document.querySelectorAll('pre').forEach(pre=>{
      if(pre.querySelector('.copy-btn')) return;
      const code = pre.querySelector('code'); if(!code) return;
      pre.classList.add('code-wrapper');
      const btn=document.createElement('button'); btn.type='button'; btn.className='copy-btn';
      btn.innerHTML='<svg viewBox="0 0 24 24" aria-hidden="true"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15V5a2 2 0 0 1 2-2h10"/></svg>';
      btn.addEventListener('click',()=>{
        const text = code.innerText.replace(/^(\s*[0-9]+\s)/gm,'');
        navigator.clipboard.writeText(text).then(()=>{
          btn.classList.add('copied');
          const prev = btn.innerHTML;
          btn.innerHTML='<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M5 12.5l4.5 4.5L19 7" stroke="var(--accent2)" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round"/></svg>';
          setTimeout(()=>{ btn.classList.remove('copied'); btn.innerHTML=prev; },1400);
        });
      });
      pre.appendChild(btn);
    });
  }
  document.addEventListener('DOMContentLoaded', addCopyButtons);

  // MINI FLOATING TOC (H2 + toggle H3) without shifting layout
  document.addEventListener('DOMContentLoaded', () => {
    const tocRoot = document.getElementById('miniTOC');
    if(!tocRoot) return;
    const content = document.querySelector('article .content');
    if(!content) return;
    const hs = content.querySelectorAll('h2, h3');
    if(!hs.length) { tocRoot.classList.add('hidden'); return; }
    const list = document.createElement('ul'); list.className='mini-toc-list';
    const title = document.createElement('div'); title.className='mini-toc-title'; title.textContent='SECTIONS';
    tocRoot.appendChild(title);
    let currentParent=null;
    hs.forEach(h=>{
      if(!h.id) h.id = h.textContent.trim().toLowerCase().replace(/[^a-z0-9]+/g,'-').replace(/^-+|-+$/g,'');
      if(h.tagName==='H2'){
        const li=document.createElement('li'); li.className='mini-toc-item depth-1';
        const a=document.createElement('a'); a.href='#'+h.id; a.textContent=h.textContent.trim();
        li.appendChild(a);
        list.appendChild(li);
        currentParent=li;
      } else { // H3
        if(!currentParent) return;
        let childWrap=currentParent.querySelector('.mini-toc-children');
        if(!childWrap){ childWrap=document.createElement('div'); childWrap.className='mini-toc-children'; currentParent.appendChild(childWrap); }
        const subLi=document.createElement('li'); subLi.className='mini-toc-item depth-2';
        const a=document.createElement('a'); a.href='#'+h.id; a.textContent=h.textContent.trim();
        subLi.appendChild(a); childWrap.appendChild(subLi);
      }
    });
    tocRoot.appendChild(list);

    // collapse toggle (only add controls to parents that actually have children)
    const headerOffset = 70; // approximate sticky header height
    function smoothScrollTo(el){
      const rect = el.getBoundingClientRect();
      const y = window.scrollY + rect.top - headerOffset - 6;
      window.scrollTo({top:y, behavior:'smooth'});
    }
    const parents = Array.from(list.querySelectorAll('.mini-toc-item.depth-1'));
    parents.forEach((parent,idx)=>{
      const kids = parent.querySelector('.mini-toc-children');
      const link = parent.querySelector('> a');
      if(!link) return;
      if(kids){
        parent.classList.add('mini-toc-collapsible');
        // collapse all by default except first collapsible
        if(idx===0){ parent.classList.add('open'); }
        const existingArrow = parent.querySelector('.mini-toc-arrow');
        let arrow = existingArrow;
        if(!arrow){
          arrow=document.createElement('span');
          arrow.className='mini-toc-arrow';
          arrow.setAttribute('role','button');
          arrow.setAttribute('aria-label','Toggle subsection');
          arrow.textContent='›';
          link.prepend(arrow);
        }
        link.addEventListener('click',e=>{
          e.preventDefault();
          const tgt=document.getElementById(link.getAttribute('href').slice(1));
          if(tgt) smoothScrollTo(tgt);
        });
        arrow.addEventListener('click',e=>{
          e.preventDefault(); e.stopPropagation();
          parent.classList.toggle('open');
          arrow.setAttribute('aria-expanded', parent.classList.contains('open'));
        });
      } else {
        // plain link
        link.addEventListener('click',e=>{
          e.preventDefault();
          const tgt=document.getElementById(link.getAttribute('href').slice(1));
          if(tgt) smoothScrollTo(tgt);
        });
      }
    });
    // Sub-item navigation
    list.querySelectorAll('.mini-toc-item.depth-2 > a').forEach(a=>{
      a.addEventListener('click',e=>{
        e.preventDefault();
        const tgt=document.getElementById(a.getAttribute('href').slice(1));
        if(tgt) smoothScrollTo(tgt);
        const parent=a.closest('.mini-toc-collapsible');
        if(parent && !parent.classList.contains('open')) parent.classList.add('open');
      });
    });
    // Ensure regular internal anchor clicks elsewhere also respect offset
    document.querySelectorAll('a[href^="#"]').forEach(a=>{
      a.addEventListener('click',ev=>{
        const hash=a.getAttribute('href');
        if(hash.length>1){
          const target=document.getElementById(hash.slice(1));
          if(target){ ev.preventDefault(); smoothScrollTo(target); history.replaceState(null,'',hash); }
        }
      });
    });

    // Active state via IntersectionObserver
  const observer = new IntersectionObserver(entries=>{
      entries.forEach(en=>{
        if(en.isIntersecting){
          const id=en.target.id;
          list.querySelectorAll('.mini-toc-item').forEach(i=>i.classList.remove('active'));
          const active = list.querySelector(`a[href="#${id}"]`);
            if(active){ active.parentElement.classList.add('active'); const parent=active.closest('.mini-toc-children'); if(parent){ parent.parentElement.classList.add('active'); }}
        }
      });
  },{rootMargin:'0px 0px -70% 0px', threshold:.1});
    hs.forEach(h=>observer.observe(h));
  });

})();
