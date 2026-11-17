/*
 * Guardiantus AV — every file, four checks.
 *
 * Files fly in from the left through four gates — hash, patterns, YARA,
 * heuristics, cheapest first — towards the shield. A clean file passes every
 * gate. A threat is stopped at the gate that recognises it and drops into the
 * quarantine vault below, where it stays restorable. Click or tap to send the
 * next file. The examples are the ones the site documents: the reverse shell
 * from the scan output and the two self-test probes from the setup page.
 */
export default function scene(stage) {
  const { THREE, frame } = stage;
  stage.lights({ ambient: 0.6, key: 2.3, rim: 30 });
  stage.environment(0.8);

  const root = new THREE.Group();
  root.scale.setScalar(0.92);
  frame.add(root);
  root.add(stage.halo(stage.accent, 8, 0.18));

  const OK = new THREE.Color('#4ade80');
  const RISK = stage.accent.clone();

  /* ------------------------------------------------------------- shield */

  // The outline of the logo's shield (200 × 200, y downwards in the SVG).
  const up = (y) => 200 - y;
  const outline = new THREE.Shape();
  outline.moveTo(100, up(20));
  outline.bezierCurveTo(122, up(34), 148, up(42), 174, up(44));
  outline.lineTo(174, up(104));
  outline.bezierCurveTo(174, up(141), 143, up(170), 100, up(184));
  outline.bezierCurveTo(57, up(170), 26, up(141), 26, up(104));
  outline.lineTo(26, up(44));
  outline.bezierCurveTo(52, up(42), 78, up(34), 100, up(20));
  const shieldGeometry = new THREE.ExtrudeGeometry(outline, { depth: 16, bevelEnabled: true, bevelThickness: 4, bevelSize: 3, bevelSegments: 3, curveSegments: 24 });
  shieldGeometry.translate(-100, -100, -8);
  shieldGeometry.scale(0.0125, 0.0125, 0.0125);
  const shieldMaterial = stage.mat.solid(0x1a0d10, { roughness: 0.28, metalness: 0.7, emissive: RISK.clone(), emissiveIntensity: 0.08 });
  const shield = new THREE.Group();
  shield.add(new THREE.Mesh(shieldGeometry, shieldMaterial), stage.edges(shieldGeometry, stage.accentHi, 0.55, 30));
  shield.position.set(1.55, 0.15, 0);
  shield.rotation.y = -0.5;
  root.add(shield);

  /* -------------------------------------------------------------- gates */

  const LAYERS = ['HASH', 'PATTERNS', 'YARA', 'HEURISTICS'];
  const gates = LAYERS.map((name, i) => {
    const group = new THREE.Group();
    group.position.set(-1.95 + i * 0.75, 0.15, 0);
    group.rotation.y = Math.PI / 2;
    const material = stage.mat.glow(stage.accentHi, { opacity: 0.55 });
    const ring = new THREE.Mesh(new THREE.TorusGeometry(0.62, 0.014, 10, 96), material);
    group.add(ring);
    const tag = stage.plate(0.9, 0.17, (g, w, h) => {
      g.fillStyle = 'rgba(242, 245, 242, 0.75)';
      g.font = stage.font.mono(Math.round(h * 0.55), 500);
      g.textAlign = 'center';
      g.textBaseline = 'middle';
      g.fillText(name, w / 2, h / 2);
    });
    tag.position.set(-1.95 + i * 0.75, 0.98, 0);
    root.add(group, tag);
    return { ring, material, flash: 0, tone: OK.clone() };
  });

  /* -------------------------------------------------------------- vault */

  const vault = new THREE.Group();
  vault.position.set(-0.85, -1.45, 0);
  const box = new THREE.BoxGeometry(1.5, 0.42, 0.7);
  vault.add(new THREE.Mesh(box, stage.mat.solid(0x120a0c, { roughness: 0.4, metalness: 0.6 })), stage.edges(box, stage.accent, 0.8));
  const vaultTag = stage.plate(1.4, 0.16, (g, w, h) => {
    g.fillStyle = 'rgba(255, 179, 187, 0.9)';
    g.font = stage.font.mono(Math.round(h * 0.55), 500);
    g.textAlign = 'center';
    g.textBaseline = 'middle';
    g.fillText('QUARANTINE · RESTORABLE', w / 2, h / 2);
  });
  vaultTag.position.set(0, 0, 0.36);
  vault.add(vaultTag);
  root.add(vault);

  /* -------------------------------------------------------------- files */

  // gate: index of the layer that convicts it; -1 = clean.
  const FILES = [
    { name: 'quarterly-report.pdf', gate: -1 },
    { name: 'sys-health-check.sh', gate: 2, found: 'Backdoor.Shell.ReverseTCP', why: '[yara] Bash reverse shell via /dev/tcp' },
    { name: 'holiday-photos.zip', gate: -1 },
    { name: 'probe.txt', gate: 0, found: 'Guardiantus.SelfTest.HashProbe', why: '[hash] the setup page’s self-test file' },
    { name: 'notes.txt', gate: -1 },
    { name: 'probe2.txt', gate: 2, found: 'Guardiantus.SelfTest.YaraProbe', why: '[yara] the setup page’s second self-test' },
  ];

  const card = (file) => (g, w, h) => {
    g.beginPath();
    if (g.roundRect) g.roundRect(0, 0, w, h, h * 0.12);
    else g.rect(0, 0, w, h);
    g.fillStyle = 'rgba(14, 10, 12, 0.92)';
    g.fill();
    g.lineWidth = h * 0.04;
    g.strokeStyle = 'rgba(242, 245, 242, 0.35)';
    g.stroke();
    // A page with a folded corner.
    const x = h * 0.18;
    const y = h * 0.2;
    const pw = h * 0.42;
    const ph = h * 0.58;
    g.fillStyle = 'rgba(242, 245, 242, 0.85)';
    g.beginPath();
    g.moveTo(x, y);
    g.lineTo(x + pw * 0.65, y);
    g.lineTo(x + pw, y + pw * 0.35);
    g.lineTo(x + pw, y + ph);
    g.lineTo(x, y + ph);
    g.closePath();
    g.fill();
    g.fillStyle = '#f2f5f2';
    g.font = stage.font.mono(Math.round(h * 0.26), 500);
    g.textBaseline = 'middle';
    g.fillText(file.name, h * 0.78, h * 0.5);
  };
  const tiles = FILES.map((file) => {
    const mesh = stage.plate(1.35, 0.32, card(file), { resolution: 280 });
    mesh.visible = false;
    root.add(mesh);
    return mesh;
  });

  let label = '';
  const plate = stage.plate(4.8, 0.36, (g, w, h) => {
    g.fillStyle = '#f2f5f2';
    let size = Math.round(h * 0.42);
    g.font = stage.font.mono(size);
    while (size > 8 && g.measureText(label).width > w * 0.96) {
      size -= 1;
      g.font = stage.font.mono(size);
    }
    g.textBaseline = 'middle';
    g.textAlign = 'center';
    g.fillText(label, w / 2, h / 2);
  });
  plate.position.set(0, -2.45, 1.2);
  frame.add(plate);
  const fit = (view) => {
    plate.visible = stage.mode === 'hero' && view.wide;
  };
  stage.onResize(fit);
  fit(stage.view);
  const say = (text) => {
    if (text === label) return;
    label = text;
    plate.userData.redraw();
  };

  stage.dust({ count: 170, radius: 6.5, color: stage.accentHi, opacity: 0.4 });

  /* ----------------------------------------------------------- behaviour */

  const START = -3.4;
  const SHIELD = 1.2;
  let current = -1;
  let x = START;
  let phase = 'gap'; // gap | flying | caught | arrived
  let clock = 0;
  let fall = 0;
  let passed = -1;

  const launch = () => {
    if (current >= 0) tiles[current].visible = false;
    current = (current + 1) % FILES.length;
    x = START;
    passed = -1;
    phase = 'flying';
    clock = 0;
    fall = 0;
    tiles[current].visible = true;
    tiles[current].material.opacity = 1;
    say(`Scanning ${FILES[current].name}…`);
  };
  stage.onClick(() => {
    if (phase === 'flying') return;
    launch();
  });

  stage.onFrame((time, delta) => {
    root.rotation.y = -0.32 + stage.yaw * 0.6;
    root.rotation.x = 0.12 + stage.pitch;
    root.position.y = Math.sin(time * 0.7) * 0.04;
    shield.rotation.y = -0.5 + Math.sin(time * 0.6) * 0.12;
    clock += delta;

    if (phase === 'gap' && clock > 0.9) launch();

    const file = current >= 0 ? FILES[current] : null;
    const tile = current >= 0 ? tiles[current] : null;

    if (phase === 'flying' && tile) {
      x += delta * 1.5;
      const stopAt = file.gate >= 0 ? -1.95 + file.gate * 0.75 - 0.05 : Infinity;
      // Each gate the file passes lights up green.
      for (let i = 0; i < gates.length; i += 1) {
        if (i > passed && x > -1.95 + i * 0.75 && (file.gate < 0 || i < file.gate)) {
          passed = i;
          gates[i].flash = 1;
          gates[i].tone.copy(OK);
        }
      }
      if (x >= stopAt) {
        x = stopAt;
        phase = 'caught';
        clock = 0;
        gates[file.gate].flash = 1.6;
        gates[file.gate].tone.copy(RISK);
        say(`THREAT ${file.found} · ${file.why} → quarantined`);
      } else if (x >= SHIELD) {
        phase = 'arrived';
        clock = 0;
        say(`${file.name} · clean · all four layers quiet`);
      }
      tile.position.set(x, 0.15 + Math.sin(x * 2.2) * 0.05, 0.02);
    } else if (phase === 'caught' && tile) {
      // Pulled down into the vault.
      fall = Math.min(1, fall + delta * 1.1);
      const eased = fall * fall * (3 - 2 * fall);
      tile.position.x = THREE.MathUtils.lerp(-1.95 + file.gate * 0.75, vault.position.x, eased);
      tile.position.y = THREE.MathUtils.lerp(0.15, vault.position.y + 0.32, eased);
      tile.scale.setScalar(1 - eased * 0.45);
      tile.material.opacity = 1 - Math.max(0, eased - 0.75) * 4;
      if (clock > 2.6) {
        phase = 'gap';
        clock = 0;
        tile.scale.setScalar(1);
      }
    } else if (phase === 'arrived' && tile) {
      x += delta * 1.2;
      tile.position.x = x;
      tile.material.opacity = Math.max(0, 1 - (x - SHIELD) * 1.6);
      shieldMaterial.emissive.copy(OK);
      if (clock > 1.6) {
        phase = 'gap';
        clock = 0;
      }
    }
    if (phase !== 'arrived') shieldMaterial.emissive.lerp(RISK, Math.min(1, delta * 2));
    shieldMaterial.emissiveIntensity = phase === 'arrived' ? 0.35 : 0.08;
    if (tile) tile.rotation.y = -root.rotation.y * 0.4;

    for (const gate of gates) {
      gate.flash = Math.max(0, gate.flash - delta * 1.2);
      gate.material.color.copy(stage.accentHi).lerp(gate.tone, Math.min(1, gate.flash));
      gate.material.opacity = 0.45 + Math.min(1, gate.flash) * 0.55;
      gate.ring.scale.setScalar(1 + Math.min(1, gate.flash) * 0.08);
    }
  });
}
