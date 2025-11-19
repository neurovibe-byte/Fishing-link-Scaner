document.addEventListener('DOMContentLoaded', () => {
  const form = document.getElementById('check-form');
  const input = document.getElementById('url-input');
  const status = document.getElementById('status');
  const resultCard = document.getElementById('result-card');
  const resultTitle = document.getElementById('result-title');
  const resultText = document.getElementById('result-text');
  const details = document.getElementById('details');

  const animateElement = (element, animation) => {
    element.style.animation = 'none';
    element.offsetHeight;
    element.style.animation = animation;
  };

  function setStatus(text, isError = false) {
    status.textContent = text;
    status.style.color = isError ? '#ef4444' : 'var(--muted)';
    animateElement(status, 'fadeIn 0.3s ease-out');
  }

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const url = input.value.trim();
    if(!url){ 
      setStatus('Введите URL для проверки', true);
      animateElement(input, 'pulse 0.5s ease');
      return;
    }

    setStatus('Анализируем...');
    resultCard.classList.add('hidden');

    try{
      const resp = await fetch('/check', {
        method: 'POST',
        headers: {'Content-Type':'application/json'},
        body: JSON.stringify({url})
      });

      if(!resp.ok) throw new Error('Ошибка сети');
      const data = await resp.json();

  resultTitle.textContent = data.result || 'Результат';
      // Показать метку доверенного сайта
      if(data.trusted){
        const badge = document.createElement('div');
        badge.textContent = 'Доверенный';
        badge.style.display = 'inline-block';
        badge.style.marginLeft = '8px';
        badge.style.padding = '2px 8px';
        badge.style.background = 'linear-gradient(90deg,#10b981,#06b6d4)';
        badge.style.borderRadius = '999px';
        badge.style.fontSize = '0.8rem';
        badge.style.color = '#032';
        resultTitle.appendChild(badge);
      }
      resultText.textContent = '';
      // Update numeric score and progress bar if present
      const scoreNumber = document.getElementById('score-number');
      const scoreFill = document.getElementById('score-fill');
      if(typeof data.score !== 'undefined' && data.score !== null){
        scoreNumber.textContent = `${data.score} / 100`;
        const pct = Math.max(0, Math.min(100, Number(data.score)));
        scoreFill.style.width = pct + '%';
        // color by range
        if(pct >= 70){
          scoreFill.style.background = 'linear-gradient(90deg,#34d399,#06b6d4)'; // green
        } else if(pct >= 40){
          scoreFill.style.background = 'linear-gradient(90deg,#f59e0b,#f97316)'; // orange
        } else {
          scoreFill.style.background = 'linear-gradient(90deg,#ef4444,#b91c1c)'; // red
        }
      } else {
        scoreNumber.textContent = '— / 100';
        scoreFill.style.width = '0%';
      }
      details.innerHTML = '';

  if(data.spoofed_brands && data.spoofed_brands.length){
        const ul = document.createElement('ul');
        data.spoofed_brands.forEach(s => { const li = document.createElement('li'); li.textContent = s; ul.appendChild(li) });
        details.appendChild(document.createElement('hr'));
        const h = document.createElement('div'); h.textContent = 'Подмены брендов:'; h.style.marginTop='8px'; details.appendChild(h);
        details.appendChild(ul);
      }

      // Показать ошибку сервера/фетча, если есть
      if(data.error){
        const err = document.createElement('div');
        err.style.color = '#ffb4b4';
        err.style.marginTop = '8px';
        err.textContent = 'Ошибка при получении содержимого: ' + data.error;
        details.appendChild(err);
      }

      // Если модель использована — покажем вероятность фишинга и пометки
      if(data.model_used){
        const mdiv = document.createElement('div');
        mdiv.style.marginTop = '8px';
        mdiv.innerHTML = `<strong>Модель:</strong> использована<br>Вероятность фишинга: ${(data.model_phishing_prob*100).toFixed(1)}%`;
        details.appendChild(mdiv);
      } else if(data.content_data){
        const cd = data.content_data;
        const info = document.createElement('div');
        info.innerHTML = `<strong>Функции страницы:</strong><br>
          Формы: ${cd.forms ? 'да' : 'нет'}<br>
          Поля для пароля: ${cd.password_fields ? 'да' : 'нет'}<br>
          Внешние скрипты: ${cd.external_scripts ? 'да' : 'нет'}<br>
          Скрытые элементы: ${cd.hidden_elements ? 'да' : 'нет'}<br>
          Подозрительные редиректы: ${cd.suspicious_redirects ? 'да' : 'нет'}`;
        details.appendChild(info);
      }

  resultCard.classList.remove('hidden');
      setStatus('Готово');

    } catch(err){
      setStatus('Ошибка: ' + (err.message || err));
    }
  });
});
