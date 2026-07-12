document$.subscribe(function() {
  var filterContainer = document.querySelector(".writeup-filters");
  var filterableGrid = document.querySelector(".writeup-grid.filterable");

  if (!filterContainer || !filterableGrid) {
    return;
  }

  var ctfSelect = filterContainer.querySelector("#writeup-ctf-filter");
  var categorySelect = filterContainer.querySelector("#writeup-category-filter");
  var resetButton = filterContainer.querySelector(".filter-reset");
  var countLabel = filterContainer.querySelector(".filter-count");
  var emptyMessage = document.querySelector(".filter-empty");
  var cards = Array.prototype.slice.call(
    filterableGrid.querySelectorAll(".writeup-card")
  );

  if (!ctfSelect || !categorySelect) {
    return;
  }

  function matchesFilter(card, filterName, selectedValue) {
    return selectedValue === "all" || card.getAttribute(filterName) === selectedValue;
  }

  function pluralizeWriteups(count) {
    return count === 1 ? "1 writeup" : count + " writeups";
  }

  function updateFilters() {
    var selectedCtf = ctfSelect.value || "all";
    var selectedCategory = categorySelect.value || "all";
    var visibleCount = 0;

    cards.forEach(function(card) {
      var shouldShow =
        matchesFilter(card, "data-ctf", selectedCtf) &&
        matchesFilter(card, "data-category", selectedCategory);

      card.classList.toggle("show", shouldShow);
      if (shouldShow) {
        visibleCount += 1;
      }
    });

    if (countLabel) {
      countLabel.textContent = pluralizeWriteups(visibleCount);
    }

    if (emptyMessage) {
      emptyMessage.hidden = visibleCount !== 0;
    }

    if (resetButton) {
      resetButton.hidden = selectedCtf === "all" && selectedCategory === "all";
    }
  }

  ctfSelect.addEventListener("change", updateFilters);
  categorySelect.addEventListener("change", updateFilters);

  if (resetButton) {
    resetButton.addEventListener("click", function() {
      ctfSelect.value = "all";
      categorySelect.value = "all";
      updateFilters();
      ctfSelect.focus();
    });
  }

  updateFilters();
});
