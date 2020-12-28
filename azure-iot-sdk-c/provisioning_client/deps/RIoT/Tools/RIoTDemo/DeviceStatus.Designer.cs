namespace RIoTDemo
{
    partial class DeviceStatus
    {
        /// <summary> 
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary> 
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Component Designer generated code

        /// <summary> 
        /// Required method for Designer support - do not modify 
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            this.pic = new System.Windows.Forms.PictureBox();
            this.status = new System.Windows.Forms.TextBox();
            this.DeviceID = new System.Windows.Forms.Label();
            this.message = new System.Windows.Forms.TextBox();
            this.pownMe = new System.Windows.Forms.Button();
            ((System.ComponentModel.ISupportInitialize)(this.pic)).BeginInit();
            this.SuspendLayout();
            // 
            // pic
            // 
            this.pic.Location = new System.Drawing.Point(19, 45);
            this.pic.Name = "pic";
            this.pic.Size = new System.Drawing.Size(187, 137);
            this.pic.TabIndex = 0;
            this.pic.TabStop = false;
            // 
            // status
            // 
            this.status.Location = new System.Drawing.Point(19, 206);
            this.status.Name = "status";
            this.status.Size = new System.Drawing.Size(104, 20);
            this.status.TabIndex = 1;
            // 
            // DeviceID
            // 
            this.DeviceID.AutoSize = true;
            this.DeviceID.Font = new System.Drawing.Font("Microsoft Sans Serif", 18F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.DeviceID.Location = new System.Drawing.Point(19, 4);
            this.DeviceID.Name = "DeviceID";
            this.DeviceID.Size = new System.Drawing.Size(136, 29);
            this.DeviceID.TabIndex = 2;
            this.DeviceID.Text = "UnknownID";
            // 
            // message
            // 
            this.message.Location = new System.Drawing.Point(19, 180);
            this.message.Name = "message";
            this.message.Size = new System.Drawing.Size(187, 20);
            this.message.TabIndex = 3;
            // 
            // pownMe
            // 
            this.pownMe.Location = new System.Drawing.Point(129, 206);
            this.pownMe.Name = "pownMe";
            this.pownMe.Size = new System.Drawing.Size(75, 23);
            this.pownMe.TabIndex = 4;
            this.pownMe.Text = "P0wn Me!";
            this.pownMe.UseVisualStyleBackColor = true;
            this.pownMe.Click += new System.EventHandler(this.pownMe_Click);
            // 
            // DeviceStatus
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.Controls.Add(this.pownMe);
            this.Controls.Add(this.message);
            this.Controls.Add(this.DeviceID);
            this.Controls.Add(this.status);
            this.Controls.Add(this.pic);
            this.Name = "DeviceStatus";
            this.Size = new System.Drawing.Size(231, 241);
            ((System.ComponentModel.ISupportInitialize)(this.pic)).EndInit();
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.PictureBox pic;
        private System.Windows.Forms.TextBox status;
        private System.Windows.Forms.Label DeviceID;
        private System.Windows.Forms.TextBox message;
        private System.Windows.Forms.Button pownMe;
    }
}
