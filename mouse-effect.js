function getRandomInt(min, max) {
    return Math.floor(Math.random() * (max - min)) + min;
}

function initMouseClick() {

    const mouseClicks = document.createElement("div");
    mouseClicks.classList.add("mouse-click");
    document.body.appendChild(mouseClicks);

    const canvas = document.createElement('canvas');

    mouseClicks.appendChild(canvas);

    const ctx = canvas.getContext('2d');
    let mousePoints = [] // {x: number, y: number, direction: number, ttl: number}[];
    let maxLineWidth = 8;

    function setDimension() {
        const style = getComputedStyle(mouseClicks);
        canvas.width = parseInt(style.getPropertyValue('width'));
        canvas.height = parseInt(style.getPropertyValue('height'));
        ctx.strokeStyle = '#fff';
    }

    function drawSpline(ctx, pts, t) {

        ctx.lineWidth = 4;
        ctx.save();

        let cp = []; // control points, as x0,y0,x1,y1,...
        const n = pts.length;

        for (var i = 0; i < n - 4; i += 2) {
            cp = cp.concat(getControlPoints(pts[i], pts[i + 1], pts[i + 2], pts[i + 3], pts[i + 4], pts[i + 5], t));
        }

        for (var i = 2; i < pts.length - 5; i += 2) {

            ctx.beginPath();
            ctx.lineWidth = i / n * maxLineWidth;
            ctx.moveTo(pts[i], pts[i + 1]);
            ctx.bezierCurveTo(cp[2 * i - 2], cp[2 * i - 1], cp[2 * i], cp[2 * i + 1], pts[i + 2], pts[i + 3]);
            ctx.stroke();
            ctx.closePath();

        }

        ctx.restore();

    }

    function drawCircle(x, y, radius, fill, stroke, strokeWidth) {
        ctx.beginPath()
        ctx.arc(x, y, radius, 0, 2 * Math.PI, false)
        if (fill) {
            ctx.fillStyle = fill
            ctx.fill()
        }
        // if (stroke) {
        //   ctx.lineWidth = 1
        //   ctx.strokeStyle = "rgba(256, 256, 256, 100)"
        //   ctx.stroke()
        // }
    }


    function updatePoints() {

        ctx.clearRect(0, 0, canvas.width, canvas.height);
        mousePoints = mousePoints.filter(mousePoint => mousePoint.ttl > 0);

        if (mousePoints.length === 0) return;

        let pts = []; // [x0, y0, x1, y1,...]

        for (const p of mousePoints) {
            if (p.directionX === 180) p.directionX++;
            if (p.directionY === 180) p.directionY++;
            p.x += ((100 / (p.directionX - 180)) % 0.1) * p.speed;
            p.y += ((100 / (p.directionY - 180)) % 0.1) * p.speed;
            drawCircle(p.x, p.y, p.radius, "rgba(256, 256, 256, " + p.ttl / 200 + ")");
            p.ttl--;
        }

    }

    window.addEventListener("resize", setDimension);
    setDimension();

    document.addEventListener('mouseup', function (e) {

        const count = getRandomInt(100, 300);

        for (let i = 0; i < count; i++) {
            mousePoints.push({
                x: e.clientX,
                y: e.clientY,
                speed: getRandomInt(10, 30),
                radius: getRandomInt(.5, 2),
                directionX: getRandomInt(0, 360),
                directionY: getRandomInt(0, 360),
                ttl: 200
            });
        }

    }, false);

    setInterval(updatePoints, 10);// setInterval(updateLine, 10);

}


function initMouseMove() {

    const mouseMove = document.createElement("div");
    mouseMove.classList.add("mouse-move");
    document.body.appendChild(mouseMove);

    const canvas = document.createElement('canvas');

    mouseMove.appendChild(canvas);

    const ctx = canvas.getContext('2d');
    let mouseLine = [] // {x: number, y: number, time: number}[];
    let maxLineWidth = 8;

    function setDimension() {
        const style = getComputedStyle(mouseMove);
        canvas.width = parseInt(style.getPropertyValue('width'));
        canvas.height = parseInt(style.getPropertyValue('height'));
        ctx.strokeStyle = '#fff';
    }

    function getControlPoints(x0, y0, x1, y1, x2, y2, t) {

        var d01 = Math.sqrt(Math.pow(x1 - x0, 2) + Math.pow(y1 - y0, 2));
        var d12 = Math.sqrt(Math.pow(x2 - x1, 2) + Math.pow(y2 - y1, 2));
        var fa = t * d01 / (d01 + d12);
        var fb = t * d12 / (d01 + d12);
        var p1x = x1 - fa * (x2 - x0);
        var p1y = y1 - fa * (y2 - y0);
        var p2x = x1 + fb * (x2 - x0);
        var p2y = y1 + fb * (y2 - y0);
        return [p1x, p1y, p2x, p2y];

    }

    function drawSpline(ctx, pts, t) {

        ctx.lineWidth = 4;
        ctx.save();

        let cp = []; // control points, as x0,y0,x1,y1,...
        const n = pts.length;

        for (var i = 0; i < n - 4; i += 2) {
            cp = cp.concat(getControlPoints(pts[i], pts[i + 1], pts[i + 2], pts[i + 3], pts[i + 4], pts[i + 5], t));
        }

        for (var i = 2; i < pts.length - 5; i += 2) {

            ctx.beginPath();
            ctx.lineWidth = i / n * maxLineWidth;
            ctx.moveTo(pts[i], pts[i + 1]);
            ctx.bezierCurveTo(cp[2 * i - 2], cp[2 * i - 1], cp[2 * i], cp[2 * i + 1], pts[i + 2], pts[i + 3]);
            ctx.stroke();
            ctx.closePath();

        }

        ctx.restore();

    }

    function updateLine() {

        ctx.clearRect(0, 0, canvas.width, canvas.height);
        mouseLine = mouseLine.filter(coordinate => coordinate.time >= +new Date() - 150);

        if (mouseLine.length === 0) return;

        let pts = []; // [x0, y0, x1, y1,...]

        for (const point of mouseLine) {
            pts.push(point.x);
            pts.push(point.y);
        }

        drawSpline(ctx, pts, 0.5);

    }

    window.addEventListener("resize", setDimension);
    setDimension();

    document.addEventListener('mousemove', function (e) {

        mouseLine.push({
            x: e.clientX,
            y: e.clientY,
            time: new Date().getTime()
        });

    }, false);

    setInterval(updateLine, 10);

}

initMouseClick();
initMouseMove();
