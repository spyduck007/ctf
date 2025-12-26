---
hide:
  - toc
---

# CTF Writeups

<div class="filter-container">
  <button class="filter-btn active" onclick="filterSelection('all')">All</button>
  <button class="filter-btn" onclick="filterSelection('LakeCTF-Quals-2025')">LakeCTF-Quals-2025</button>
  <button class="filter-btn" onclick="filterSelection('crypto')">crypto</button>
  <button class="filter-btn" onclick="filterSelection('web')">web</button>
</div>

<div class="writeup-grid filterable">

  <a href="the-phantom-menace/" class="writeup-card" data-tags="LakeCTF-Quals-2025 crypto">
    <div class="card-content">
      <div class="card-header">
        <span class="card-date">2025-11-28</span>
        <h3 class="card-title">The Phantom Menace</h3>
      </div>
      <div class="card-tags">
        <span class="tag">LakeCTF-Quals-2025</span><span class="tag">crypto</span>
      </div>
    </div>
  </a>

  <a href="revenge-of-the-sith/" class="writeup-card" data-tags="LakeCTF-Quals-2025 crypto">
    <div class="card-content">
      <div class="card-header">
        <span class="card-date">2025-11-28</span>
        <h3 class="card-title">Revenge of the Sith</h3>
      </div>
      <div class="card-tags">
        <span class="tag">LakeCTF-Quals-2025</span><span class="tag">crypto</span>
      </div>
    </div>
  </a>

  <a href="attack-of-the-clones/" class="writeup-card" data-tags="LakeCTF-Quals-2025 crypto">
    <div class="card-content">
      <div class="card-header">
        <span class="card-date">2025-11-28</span>
        <h3 class="card-title">Attack of the Clones</h3>
      </div>
      <div class="card-tags">
        <span class="tag">LakeCTF-Quals-2025</span><span class="tag">crypto</span>
      </div>
    </div>
  </a>

  <a href="quantum-vernam/" class="writeup-card" data-tags="LakeCTF-Quals-2025 crypto">
    <div class="card-content">
      <div class="card-header">
        <span class="card-date">2025-11-28</span>
        <h3 class="card-title">Quantum Vernam</h3>
      </div>
      <div class="card-tags">
        <span class="tag">LakeCTF-Quals-2025</span><span class="tag">crypto</span>
      </div>
    </div>
  </a>

  <a href="gamblecore/" class="writeup-card" data-tags="LakeCTF-Quals-2025 web">
    <div class="card-content">
      <div class="card-header">
        <span class="card-date">2025-11-28</span>
        <h3 class="card-title">gamblecore</h3>
      </div>
      <div class="card-tags">
        <span class="tag">LakeCTF-Quals-2025</span><span class="tag">web</span>
      </div>
    </div>
  </a>

  <a href="ez-part/" class="writeup-card" data-tags="LakeCTF-Quals-2025 crypto">
    <div class="card-content">
      <div class="card-header">
        <span class="card-date">2025-11-28</span>
        <h3 class="card-title">Ez Part</h3>
      </div>
      <div class="card-tags">
        <span class="tag">LakeCTF-Quals-2025</span><span class="tag">crypto</span>
      </div>
    </div>
  </a>

  <a href="guess-flag/" class="writeup-card" data-tags="LakeCTF-Quals-2025 crypto">
    <div class="card-content">
      <div class="card-header">
        <span class="card-date">2025-11-28</span>
        <h3 class="card-title">Guess Flag</h3>
      </div>
      <div class="card-tags">
        <span class="tag">LakeCTF-Quals-2025</span><span class="tag">crypto</span>
      </div>
    </div>
  </a>
</div>

<script>
function filterSelection(c) {
  var x, i;
  x = document.getElementsByClassName("writeup-card");
  var btns = document.getElementsByClassName("filter-btn");
  
  // Update active button state
  for (i = 0; i < btns.length; i++) {
    if (btns[i].innerText.toLowerCase() === c.toLowerCase() || (c === 'all' && btns[i].innerText === 'All')) {
      btns[i].classList.add("active");
    } else {
      btns[i].classList.remove("active");
    }
  }

  if (c == "all") c = "";
  for (i = 0; i < x.length; i++) {
    w3RemoveClass(x[i], "show");
    if (x[i].getAttribute("data-tags").indexOf(c) > -1) w3AddClass(x[i], "show");
  }
}

function w3AddClass(element, name) {
  var i, arr1, arr2;
  arr1 = element.className.split(" ");
  arr2 = name.split(" ");
  for (i = 0; i < arr2.length; i++) {
    if (arr1.indexOf(arr2[i]) == -1) {element.className += " " + arr2[i];}
  }
}

function w3RemoveClass(element, name) {
  var i, arr1, arr2;
  arr1 = element.className.split(" ");
  arr2 = name.split(" ");
  for (i = 0; i < arr2.length; i++) {
    while (arr1.indexOf(arr2[i]) > -1) {
      arr1.splice(arr1.indexOf(arr2[i]), 1);     
    }
  }
  element.className = arr1.join(" ");
}

// Initialize
filterSelection("all")
</script>
