using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Drawing;
using System.Data;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace RIoTDemo
{
    internal enum CurrentState
    {
        Good,
        OldFirmware,
        BadFirmware
    }

    public partial class DeviceStatus : UserControl
    {
        internal string Id="Unknown";
        internal int MyVersionNumber = 0;
        internal CurrentState State = CurrentState.BadFirmware;
        internal Bitmap Picture = new Bitmap(100, 100);
        String LastMessage;
        internal DateTime LastMessageTime;
        internal KnownColor PicColor = KnownColor.Black;

        internal bool AmIPOwned = false;
        internal bool P0wnedStatusChanged = false;


        public DeviceStatus()
        {
            InitializeComponent();
        }

        void SetVersionNumber(int newVersionNumber)
        {
            if (newVersionNumber == MyVersionNumber) return;
            MyVersionNumber = newVersionNumber;
            UpdateGUI();
        }
        internal void NotifyNewMessage(string m)
        {
            LastMessage = m;
            LastMessageTime = DateTime.Now;

        }

        internal void UpdateGUI()
        {
            if(LastMessage!=null)
            {
                message.Text = LastMessage;
                pic.BackColor = Color.FromKnownColor((KnownColor) PicColor);
                LastMessage = null;
            }

            if (AmIPOwned)
            {
                pownMe.BackColor = Color.Red;
            }
            else
            {
                pownMe.BackColor = Color.Green;
            }

            //this.pic. = Picture;
            this.DeviceID.Text = Id;
            this.status.Text = $"Version Number {MyVersionNumber}";
            switch(State)
            {
                case CurrentState.Good:
                    this.BackColor = Color.Green;
                    break;
                case CurrentState.OldFirmware:
                    this.BackColor = Color.Yellow;
                    break;
                case CurrentState.BadFirmware:
                    this.BackColor = Color.Red;
                    break;
                default:
                    this.BackColor = Color.Red;
                    break;
            }



        }

        private void pownMe_Click(object sender, EventArgs e)
        {
            AmIPOwned = !AmIPOwned;
            P0wnedStatusChanged = true;


        }
    }
}
