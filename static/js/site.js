// Simple client-side search using pre-built /index.json
(function(){
  // BLOG PAGE SEARCH
  const blogInput = document.getElementById('blogSearchInput');
  const postsContainer = document.getElementById('postsContainer');
  const stats = document.getElementById('searchStats');
  let INDEX = [];
  if(blogInput){
    fetch('/index.json')
      .then(r=>r.json())
      .then(j=>{ INDEX=j; if(stats) stats.textContent = `${INDEX.length} posts`; });
    const deb=(fn,ms)=>{let t;return (...a)=>{clearTimeout(t);t=setTimeout(()=>fn(...a),ms)};};
    function filter(){
      const q = blogInput.value.trim().toLowerCase();
      let shown = 0;
      postsContainer.querySelectorAll('.post-card').forEach(card=>{
        if(!q){ card.style.display='flex'; shown++; return; }
        const hay = `${card.dataset.title} ${card.dataset.summary} ${card.dataset.content}`.toLowerCase();
        card.style.display = hay.includes(q) ? 'flex' : 'none';
        if(hay.includes(q)) shown++;
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

  // SIMPLE TOC: H2 items; add arrow and toggle only if H3 exists under that H2
  document.addEventListener('DOMContentLoaded', () => {
    const toc = document.getElementById('miniTOC');
    if(!toc) return;
    const content = document.querySelector('article .content');
    if(!content){ toc.classList.add('hidden'); return; }

    const all = Array.from(content.querySelectorAll('h2, h3'));
    if(!all.length){ toc.classList.add('hidden'); return; }

    const title = document.createElement('div');
    title.className = 'mini-toc-title';
    title.textContent = 'SECTIONS';
    toc.appendChild(title);

    const root = document.createElement('ul');
    root.className = 'mini-toc-list';

    const slug = (t)=> t.trim().toLowerCase().replace(/[^a-z0-9]+/g,'-').replace(/^-+|-+$/g,'');
    const makeLink = (h)=>{
      if(!h.id) h.id = slug(h.textContent);
      const a = document.createElement('a');
      a.href = `#${h.id}`;
      a.textContent = h.textContent.trim();
      return a;
    };

    let currentLi = null;
    let currentChildren = null;

    all.forEach(h => {
      if(h.tagName === 'H2'){
        currentLi = document.createElement('li');
        currentLi.className = 'mini-toc-item depth-1';
        currentLi.appendChild(makeLink(h));
        root.appendChild(currentLi);
        currentChildren = null;
      } else if(h.tagName === 'H3' && currentLi){
        if(!currentChildren){
          // first H3 seen for this H2: add arrow and children list
          currentChildren = document.createElement('ul');
          currentChildren.className = 'mini-toc-children';

          const liForThisH2 = currentLi; // capture in closure
          const parentLink = liForThisH2.querySelector('a');
          const arrow = document.createElement('span');
          arrow.className = 'mini-toc-arrow';
          arrow.textContent = '▸'; // collapsed by default (chevron)

          liForThisH2.classList.add('mini-toc-collapsible');
          // Place the arrow INSIDE the link so it aligns to the link height and doesn't move when children expand
          parentLink.insertBefore(arrow, parentLink.firstChild);

          const update = () => { arrow.textContent = liForThisH2.classList.contains('open') ? '▾' : '▸'; };
          const toggle = (e) => { e.preventDefault(); liForThisH2.classList.toggle('open'); update(); };
          arrow.addEventListener('click', toggle);
          arrow.setAttribute('tabindex','0');
          arrow.addEventListener('keydown', e=>{ if(e.key==='Enter' || e.key===' ') toggle(e); });
          update();

          liForThisH2.appendChild(currentChildren);
        }

        const sub = document.createElement('li');
        sub.className = 'mini-toc-item depth-2';
        sub.appendChild(makeLink(h));
        currentChildren.appendChild(sub);
      }
    });

    if(!root.children.length){ toc.classList.add('hidden'); return; }
    toc.appendChild(root);
  });

})();
