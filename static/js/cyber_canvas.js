/**
 * Digital Footprint Intelligence - Animated Cyber Matrix Canvas
 * Interactive digital node matrix with connecting vectors and emerald/sage/mint glowing pulses.
 */

(function () {
    const canvas = document.getElementById('cyber-canvas');
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    let width = (canvas.width = window.innerWidth);
    let height = (canvas.height = window.innerHeight);

    let particles = [];
    const particleCount = Math.min(85, Math.floor(window.innerWidth / 16));
    const maxDistance = 145;

    let mouse = { x: null, y: null, radius: 170 };

    window.addEventListener('resize', function () {
        width = canvas.width = window.innerWidth;
        height = canvas.height = window.innerHeight;
        initParticles();
    });

    window.addEventListener('mousemove', function (e) {
        mouse.x = e.clientX;
        mouse.y = e.clientY;
    });

    window.addEventListener('mouseout', function () {
        mouse.x = null;
        mouse.y = null;
    });

    class Particle {
        constructor() {
            this.x = Math.random() * width;
            this.y = Math.random() * height;
            this.vx = (Math.random() - 0.5) * 0.7;
            this.vy = (Math.random() - 0.5) * 0.7;
            this.radius = Math.random() * 2 + 1;
            // Alternating Mint Green, Emerald Green, and Sage Green tones
            const rand = Math.random();
            if (rand < 0.4) {
                this.color = 'rgba(110, 231, 183, '; // Mint green
                this.shadow = '#6ee7b7';
            } else if (rand < 0.75) {
                this.color = 'rgba(52, 211, 153, ';  // Emerald green
                this.shadow = '#34d399';
            } else {
                this.color = 'rgba(132, 169, 140, '; // Sage green
                this.shadow = '#84a98c';
            }
            this.baseAlpha = Math.random() * 0.55 + 0.25;
        }

        update() {
            this.x += this.vx;
            this.y += this.vy;

            if (this.x < 0 || this.x > width) this.vx = -this.vx;
            if (this.y < 0 || this.y > height) this.vy = -this.vy;

            // Mouse repulsion & interaction
            if (mouse.x !== null && mouse.y !== null) {
                const dx = mouse.x - this.x;
                const dy = mouse.y - this.y;
                const dist = Math.sqrt(dx * dx + dy * dy);
                if (dist < mouse.radius) {
                    const force = (mouse.radius - dist) / mouse.radius;
                    this.x -= (dx / dist) * force * 3;
                    this.y -= (dy / dist) * force * 3;
                }
            }
        }

        draw() {
            ctx.beginPath();
            ctx.arc(this.x, this.y, this.radius, 0, Math.PI * 2);
            ctx.fillStyle = this.color + this.baseAlpha + ')';
            ctx.shadowBlur = 9;
            ctx.shadowColor = this.shadow;
            ctx.fill();
            ctx.shadowBlur = 0;
        }
    }

    function initParticles() {
        particles = [];
        for (let i = 0; i < particleCount; i++) {
            particles.push(new Particle());
        }
    }

    function animate() {
        ctx.clearRect(0, 0, width, height);

        // Connect nearby particles with subtle sage & emerald glowing vectors
        for (let i = 0; i < particles.length; i++) {
            for (let j = i + 1; j < particles.length; j++) {
                const dx = particles[i].x - particles[j].x;
                const dy = particles[i].y - particles[j].y;
                const dist = Math.sqrt(dx * dx + dy * dy);

                if (dist < maxDistance) {
                    const alpha = (1 - dist / maxDistance) * 0.24;
                    ctx.beginPath();
                    ctx.moveTo(particles[i].x, particles[i].y);
                    ctx.lineTo(particles[j].x, particles[j].y);
                    ctx.strokeStyle = `rgba(52, 211, 153, ${alpha})`;
                    ctx.lineWidth = 0.85;
                    ctx.stroke();
                }
            }
        }

        // Draw and update each particle
        for (let i = 0; i < particles.length; i++) {
            particles[i].update();
            particles[i].draw();
        }

        requestAnimationFrame(animate);
    }

    initParticles();
    animate();
})();
