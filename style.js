class GradientAnimator {
  constructor() {
    this.startTime = parseInt(localStorage.getItem('gradientStartTime')) || Date.now();
    this.isAnimating = false;
    this.animationSpeed = 1;
    this.targetSpeed = 0;
    this.elapsed = 0;

    localStorage.setItem('gradientStartTime', this.startTime);

    this.animate = this.animate.bind(this);
    this.handleVisibilityChange = this.handleVisibilityChange.bind(this);
    this.checkFocus = this.checkFocus.bind(this);
  }

  setTargetSpeed(speed) {
    this.targetSpeed = speed;

    if (speed > 0 && !this.isAnimating) {
      this.start();
    } else if (speed === 0 && this.isAnimating) {
      this.stop();
    }
  }

  start() {
    if (!this.isAnimating) {
      document.body.classList.add('js-gradient');
      this.isAnimating = true;
      this.setupEventListeners();
      this.animate();
      this.checkFocus();
    }
  }

  stop() {
    this.isAnimating = false;
    document.body.classList.remove('js-gradient');
  }

  animate() {
    if (!this.isAnimating) return;

    if (Math.abs(this.targetSpeed) < 0.001) {
      requestAnimationFrame(this.animate); // Keep checking in case targetSpeed changes again
      return;
    }

    const speedDiff = this.targetSpeed - this.animationSpeed;
    this.animationSpeed += speedDiff * 0.05;

    const now = Date.now();
    this.elapsed += (now - this.startTime) * this.animationSpeed;
    this.startTime = now;

    const duration = 15000;
    const progress = (this.elapsed % duration) / duration;

    const angle = progress * Math.PI * 2;
    const scale = 100;
    const offset = 50;

    const x = offset + Math.cos(angle) * (scale / 2);
    const y = offset + Math.sin(angle) * (scale / 2);

    document.body.style.backgroundPosition = `${x}% ${y}%`;

    requestAnimationFrame(this.animate);
  }

  setupEventListeners() {
    document.addEventListener('visibilitychange', this.handleVisibilityChange);
    window.addEventListener('focus', this.checkFocus);
  }

  handleVisibilityChange() {
    if (document.hidden) {
      this.stop();
    } else if (this.targetSpeed > 0) {
      this.start();
    }
  }

  checkFocus() {
    if (document.hasFocus() && this.targetSpeed > 0) {
      this.start();
    }
  }
}