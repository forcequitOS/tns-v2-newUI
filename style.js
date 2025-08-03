class GradientAnimator {
  constructor() {
    this.startTime = parseInt(localStorage.getItem('gradientStartTime')) || Date.now();
    this.isAnimating = false;
    this.animationSpeed = 1;
    this.targetSpeed = 0;
    this.elapsed = 0;
    this.rotation = 0;
    localStorage.setItem('gradientStartTime', this.startTime);
    this.animate = this.animate.bind(this);
    this.handleVisibilityChange = this.handleVisibilityChange.bind(this);
    this.checkFocus = this.checkFocus.bind(this);
    
    this.initializeGradientElement();
  }

  initializeGradientElement() {
    const existing = document.querySelector('.gradient-overlay');
    if (existing) existing.remove();

    document.documentElement.style.setProperty('--gradient-rotation', '0deg');
    document.documentElement.style.setProperty('--gradient-translate-x', '-70%');
    document.documentElement.style.setProperty('--gradient-translate-y', '-70%');
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
      requestAnimationFrame(this.animate);
      return;
    }

    const speedDiff = this.targetSpeed - this.animationSpeed;
    this.animationSpeed += speedDiff * 0.05;

    const now = Date.now();
    const deltaTime = now - this.startTime;
    this.startTime = now;

    this.elapsed += deltaTime * this.animationSpeed;

    const duration = 7500;
    const progress = (this.elapsed % duration) / duration;
    const angle = progress * Math.PI * 2;

    const radius = 2;
    const centerOffset = 50;
    
    const x = centerOffset + Math.cos(angle) * radius;
    const y = centerOffset + Math.sin(angle) * radius;

    const translateX = -70 + (x - 50) * 0.05;
    const translateY = -70 + (y - 50) * 0.05;
    
    document.documentElement.style.setProperty('--gradient-translate-x', `${translateX}%`);
    document.documentElement.style.setProperty('--gradient-translate-y', `${translateY}%`);

    this.rotation += (deltaTime * this.animationSpeed * 360) / 30000;
    this.rotation = this.rotation % 360;
    document.documentElement.style.setProperty('--gradient-rotation', `${this.rotation}deg`);

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