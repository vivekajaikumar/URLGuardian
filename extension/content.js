// content.js


function extractURLs() {
  const links = document.querySelectorAll('a'); 
  const urls = [];

  //href
  links.forEach(link => {
    const href = link.href;

    
    if (href.includes('http') && !href.includes('google.com')) {
      urls.push(href);
    }
  });

  // Send the URLs to the back script
  chrome.runtime.sendMessage({ urls: urls });

  // Send url
  fetch('http://localhost:5000/log_urls', {
      method: 'POST',
      headers: {
          'Content-Type': 'application/json'
      },
      body: JSON.stringify({ urls: urls })
  })
  .then(response => response.json())
  .then(data => console.log('Server response:', data))
  .catch(error => console.error('Error sending URLs to server:', error));
}


extractURLs();
