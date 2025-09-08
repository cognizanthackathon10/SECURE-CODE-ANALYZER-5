


function unsafeRenderFromLocation() {

  const params = new URLSearchParams(window.location.search);
  const msg = params.get('msg') || 'hello';
  document.getElementById('out').innerHTML = msg; 
}

function unsafeDocumentWrite() {
  const val = new URL(location).searchParams.get('html');
  document.write(val); 
}


function runHashEval() {
  const code = location.hash.slice(1); 

  eval(code);
}


function saveToken(token) {
  localStorage.setItem('token', token); 
}


function doRedirect() {
  const params = new URLSearchParams(window.location.search);
  const dest = params.get('next');
  if (dest) {
    window.location = dest; 
  }
}


function showAdminPanel(user) {
  if (user && user.role === 'admin') { 
    document.getElementById('admin').style.display = 'block';
  }
}


const React = require('react');
function BadReact({ html }) {
  return React.createElement('div', { dangerouslySetInnerHTML: { __html: html } });
}


