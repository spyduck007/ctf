document$.subscribe(function() {
  var filterContainer = document.querySelector(".filter-container");
  var filterableGrid = document.querySelector(".writeup-grid.filterable");

  if (!filterContainer || !filterableGrid) {
    return;
  }

  var buttons = Array.prototype.slice.call(
    filterContainer.querySelectorAll(".filter-btn")
  );
  var cards = Array.prototype.slice.call(
    filterableGrid.querySelectorAll(".writeup-card")
  );

  function setFilter(filter) {
    buttons.forEach(function(button) {
      var isActive = button.getAttribute("data-filter") === filter;
      button.classList.toggle("active", isActive);
      button.setAttribute("aria-pressed", isActive ? "true" : "false");
    });

    cards.forEach(function(card) {
      var tags = (card.getAttribute("data-tags") || "").split(/\s+/);
      var shouldShow = filter === "all" || tags.indexOf(filter) !== -1;
      card.classList.toggle("show", shouldShow);
    });
  }

  buttons.forEach(function(button) {
    button.addEventListener("click", function() {
      setFilter(button.getAttribute("data-filter") || "all");
    });
  });

  setFilter("all");
});
